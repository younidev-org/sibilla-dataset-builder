//! Exact deduplication and deterministic, group-aware dataset assembly.
use anyhow::{Context, Result, bail};
use arrow_schema::{DataType, Field, Schema};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sibilla_output::{Row, extraction_schema};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
    path::{Path, PathBuf},
    sync::Arc,
};
#[derive(Default)]
struct Samples {
    rows: BTreeMap<String, Row>,
    spool: Option<PathBuf>,
    labels: BTreeMap<String, u64>,
    group_column: Option<String>,
    quarantined: BTreeSet<String>,
    duplicates: usize,
    conflicts: usize,
    excluded: usize,
}
impl Samples {
    fn add(&mut self, row: Row, quarantine: bool) -> Result<()> {
        if row.get("feature_schema_version").and_then(Value::as_str)
            != Some(sibilla_schema::SCHEMA_VERSION)
            || row.get("file_format").and_then(Value::as_str) != Some("pdf")
            || row.get("extractor_version").and_then(Value::as_str)
                != Some(env!("CARGO_PKG_VERSION"))
        {
            bail!("incompatible format, schema or extractor version");
        }
        let Some(value) = row.get("label").filter(|v| !v.is_null()) else {
            self.excluded += 1;
            return Ok(());
        };
        let label = value.as_u64().context("invalid label")?;
        if label > 1 {
            bail!("invalid label");
        }
        let status = row.get("extraction_status").and_then(Value::as_str);
        let Some(id) = row
            .get("sample_id")
            .and_then(Value::as_str)
            .map(str::to_owned)
        else {
            if matches!(status, Some("success" | "partial")) {
                bail!("missing sample identity");
            }
            self.excluded += 1;
            return Ok(());
        };
        if id.len() != 64
            || !id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            bail!("invalid SHA-256 identity");
        }
        if let Some(previous) = self.labels.insert(id.clone(), label)
            && previous != label
        {
            self.conflicts += 1;
            if !quarantine {
                bail!("conflicting labels for sample {id}");
            }
            self.rows.remove(&id);
            self.quarantined.insert(id);
            return Ok(());
        }
        if !matches!(status, Some("success" | "partial")) {
            self.excluded += 1;
            return Ok(());
        }
        if self.quarantined.contains(&id) {
            self.duplicates += 1;
            return Ok(());
        }
        if let Some(previous) = self.rows.get(&id) {
            if let Some(column) = &self.group_column
                && previous.get(column) != row.get(column)
            {
                bail!("duplicate sample has inconsistent grouping metadata");
            }

            if previous.get("label") != row.get("label") {
                self.conflicts += 1;
                if !quarantine {
                    bail!("conflicting labels for sample {id}");
                }
                self.rows.remove(&id);
                self.quarantined.insert(id);
            } else {
                self.duplicates += 1;
            }
        } else {
            if let Some(directory) = &self.spool {
                serde_json::to_writer(std::fs::File::create(directory.join(&id))?, &row)?;
                let mut metadata = BTreeMap::from([("label".to_owned(), row["label"].clone())]);
                if let Some(column) = &self.group_column {
                    metadata.insert(
                        column.clone(),
                        row.get(column).cloned().unwrap_or(Value::Null),
                    );
                }
                self.rows.insert(id, metadata);
            } else {
                self.rows.insert(id, row);
            }
        }
        Ok(())
    }
    fn records(&self) -> impl Iterator<Item = Result<Row>> + '_ {
        self.rows.iter().map(|(id, row)| {
            if let Some(directory) = &self.spool {
                Ok(serde_json::from_reader(std::fs::File::open(
                    directory.join(id),
                )?)?)
            } else {
                Ok(row.clone())
            }
        })
    }
}
fn assign(
    rows: &BTreeMap<String, Row>,
    group: Option<&str>,
    split: [u64; 3],
    seed: u64,
) -> Result<BTreeMap<String, String>> {
    let mut groups: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (id, row) in rows {
        let key = if let Some(column) = group {
            let value = row
                .get(column)
                .filter(|v| !v.is_null())
                .context("missing grouping value")?;
            format!("group:{value}")
        } else {
            format!("sample:{id}")
        };
        groups.entry(key).or_default().push(id.clone());
    }
    let mut groups: Vec<_> = groups.into_iter().collect();
    groups.sort_by_key(|(group, _)| Sha256::digest(format!("{seed}:{group}")).to_vec());
    let mut total = [0usize; 2];
    for row in rows.values() {
        total[row["label"].as_u64().context("label")? as usize] += 1;
    }
    let mut counts = [[0usize; 2]; 3];
    let names = ["train", "validation", "test"];
    let mut assignments = BTreeMap::new();
    for (_, ids) in groups {
        let mut labels = [0usize; 2];
        for id in &ids {
            labels[rows[id]["label"].as_u64().context("label")? as usize] += 1;
        }
        let best = (0..3)
            .filter(|&s| split[s] > 0)
            .min_by(|&a, &b| {
                let cost = |s: usize| -> f64 {
                    (0..2)
                        .filter(|&l| labels[l] > 0)
                        .map(|l| {
                            (counts[s][l] as f64 + labels[l] as f64 / 2.0)
                                / (total[l].max(1) as f64 * split[s] as f64 / 100.0)
                        })
                        .sum()
                };
                cost(a).total_cmp(&cost(b))
            })
            .context("empty split")?;
        for l in 0..2 {
            counts[best][l] += labels[l];
        }
        for id in ids {
            assignments.insert(id, names[best].to_owned());
        }
    }
    Ok(assignments)
}
pub fn build(
    inputs: &[PathBuf],
    output: &Path,
    split: [u64; 3],
    seed: u64,
    group: Option<&str>,
    quarantine: bool,
) -> Result<()> {
    if split.iter().any(|&p| p > 100) || split.iter().sum::<u64>() != 100 {
        bail!("split percentages must sum to 100");
    }
    if output.exists() {
        bail!("dataset output already exists");
    }
    let schema = extraction_schema();
    if let Some(column) = group
        && !schema.fields().iter().any(|f| f.name() == column)
    {
        bail!("unknown group column");
    }
    let input_spool = tempfile::tempdir()?;
    let mut samples = Samples {
        spool: Some(input_spool.path().to_owned()),
        group_column: group.map(str::to_owned),
        ..Samples::default()
    };
    // shortcut: identity/group metadata remains in memory; external sorting is needed for million-sample corpora.
    for path in inputs {
        sibilla_output::read(path, schema.clone(), |row| samples.add(row, quarantine))?;
    }
    if samples.rows.is_empty() {
        bail!("no labeled extractable samples");
    }
    if group.is_none() {
        eprintln!(
            "Warning: no grouping metadata; exact deduplication does not prevent near-duplicate or family leakage"
        );
    }
    let assignments = assign(&samples.rows, group, split, seed)?;
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent)?;
    let staging = tempfile::tempdir_in(parent)?;
    let root = staging.path();
    sibilla_output::write(
        &root.join("manifest.parquet"),
        schema.clone(),
        samples.records(),
    )?;
    let feature_fields: Vec<_> = schema
        .fields()
        .iter()
        .filter(|f| {
            f.name() == "sample_id"
                || (f.name().starts_with("extraction_common_features_")
                    && !f.name().ends_with("sha256"))
                || f.name().starts_with("extraction_format_features_")
        })
        .cloned()
        .collect();
    sibilla_output::write(
        &root.join("features.parquet"),
        Arc::new(Schema::new(feature_fields)),
        samples.records(),
    )?;
    let split_schema = Arc::new(Schema::new(vec![
        Field::new("sample_id", DataType::Utf8, false),
        Field::new("split", DataType::Utf8, false),
    ]));
    let mut split_counts = BTreeMap::new();
    for name in ["train", "validation", "test"] {
        let rows: Vec<_> = assignments
            .iter()
            .filter(|(_, s)| s.as_str() == name)
            .map(|(id, s)| {
                BTreeMap::from([
                    ("sample_id".into(), Value::from(id.clone())),
                    ("split".into(), Value::from(s.clone())),
                ])
            })
            .collect();
        split_counts.insert(name, rows.len());
        sibilla_output::write(
            &root.join(format!("splits/{name}.parquet")),
            split_schema.clone(),
            rows.into_iter().map(Ok),
        )?;
    }
    let mut null_counts: BTreeMap<String, usize> = schema
        .fields()
        .iter()
        .map(|f| (f.name().clone(), 0))
        .collect();
    for row in samples.records() {
        let row = row?;
        for (name, count) in &mut null_counts {
            if row.get(name).is_none_or(Value::is_null) {
                *count += 1;
            }
        }
    }
    let mut class_counts: BTreeMap<String, BTreeMap<String, usize>> = BTreeMap::new();
    for (id, row) in &samples.rows {
        *class_counts
            .entry(assignments[id].clone())
            .or_default()
            .entry(row["label"].to_string())
            .or_default() += 1;
    }
    let null_rates: BTreeMap<_, _> = null_counts
        .iter()
        .map(|(key, count)| (key.clone(), *count as f64 / samples.rows.len() as f64))
        .collect();
    let report = json!({"samples":samples.rows.len(),"duplicates":samples.duplicates,"conflicts":samples.conflicts,"quarantined_sample_ids":samples.quarantined,"excluded":samples.excluded,"splits":split_counts,"null_counts":null_counts,"null_rates":null_rates,"class_counts_per_split":class_counts});
    write_synced(
        root.join("report.json"),
        serde_json::to_vec_pretty(&report)?,
    )?;
    let mut hashes = BTreeMap::new();
    for path in [
        "manifest.parquet",
        "features.parquet",
        "splits/train.parquet",
        "splits/validation.parquet",
        "splits/test.parquet",
        "report.json",
    ] {
        let mut file = std::fs::File::open(root.join(path))?;
        let mut hash = Sha256::new();
        let mut bytes = [0; 65536];
        loop {
            let n = file.read(&mut bytes)?;
            if n == 0 {
                break;
            }
            hash.update(&bytes[..n]);
        }
        hashes.insert(path, format!("{:x}", hash.finalize()));
    }
    write_synced(
        root.join("dataset_metadata.json"),
        serde_json::to_vec_pretty(
            &json!({"schema":sibilla_schema::SCHEMA_VERSION,"extractor_version":env!("CARGO_PKG_VERSION"),"seed":seed,"split":split,"group_column":group,"artifact_sha256":hashes,"strategy":"seeded group allocation with label balancing","identity_column":"sample_id is a join key; remove before training"}),
        )?,
    )?;
    std::fs::File::open(root)?.sync_all()?;
    // Linux no-replace rename keeps a concurrent creator's directory intact.
    use std::os::unix::ffi::OsStrExt;
    let from = std::ffi::CString::new(root.as_os_str().as_bytes())?;
    let to = std::ffi::CString::new(output.as_os_str().as_bytes())?;
    if unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            from.as_ptr(),
            libc::AT_FDCWD,
            to.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    let _ = staging.keep();
    std::fs::File::open(parent)?.sync_all()?;
    Ok(())
}
fn write_synced(path: PathBuf, bytes: Vec<u8>) -> Result<()> {
    use std::io::Write;
    let mut file = std::fs::File::create(path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn conflicting_label_is_detected_even_when_second_row_failed() {
        let make = |label, status: &str| {
            BTreeMap::from([
                ("sample_id".into(), Value::from("a".repeat(64))),
                ("label".into(), Value::from(label)),
                ("file_format".into(), Value::from("pdf")),
                (
                    "feature_schema_version".into(),
                    Value::from(sibilla_schema::SCHEMA_VERSION),
                ),
                (
                    "extractor_version".into(),
                    Value::from(env!("CARGO_PKG_VERSION")),
                ),
                ("extraction_status".into(), Value::from(status)),
            ])
        };
        let mut samples = Samples::default();
        samples.add(make(0, "success"), false).unwrap();
        assert!(samples.add(make(1, "failed"), false).is_err());
        let mut samples = Samples::default();
        samples.add(make(0, "success"), true).unwrap();
        samples.add(make(1, "failed"), true).unwrap();
        assert!(samples.rows.is_empty());
        assert_eq!(samples.conflicts, 1);
        let mut samples = Samples {
            group_column: Some("collection_id".into()),
            ..Samples::default()
        };
        let mut a = make(0, "success");
        a.insert("collection_id".into(), Value::from("A"));
        let mut b = make(0, "success");
        b.insert("collection_id".into(), Value::from("B"));
        samples.add(a, true).unwrap();
        assert!(samples.add(b, true).is_err());
    }
    #[test]
    fn groups_never_cross_partitions_and_seed_is_reproducible() {
        let rows = (0..30)
            .map(|i| {
                (
                    format!("{i:064x}"),
                    BTreeMap::from([
                        ("label".into(), Value::from(i % 2)),
                        ("collection_id".into(), Value::from(format!("g{}", i / 3))),
                    ]),
                )
            })
            .collect();
        let assigned = assign(&rows, Some("collection_id"), [70, 15, 15], 42).unwrap();
        assert_eq!(
            assigned,
            assign(&rows, Some("collection_id"), [70, 15, 15], 42).unwrap()
        );
        let mut groups = BTreeMap::new();
        for (id, row) in rows {
            let group = row["collection_id"].to_string();
            if let Some(previous) = groups.insert(group, assigned[&id].clone()) {
                assert_eq!(previous, assigned[&id]);
            }
        }
    }
}
