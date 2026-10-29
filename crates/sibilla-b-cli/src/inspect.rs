use anyhow::Result;
use serde_json::{Value, json};
use std::{collections::BTreeMap, path::Path};
/// Read every extraction row with bounded sample storage and report quality and missingness.
pub fn run(path: &Path, as_json: bool, columns: bool) -> Result<()> {
    let schema = sibilla_b_output::extraction_schema();
    let mut rows = 0u64;
    let mut statuses = BTreeMap::<String, u64>::new();
    let mut labels = BTreeMap::<String, u64>::new();
    let mut errors = BTreeMap::<String, u64>::new();
    let mut missing: BTreeMap<String, u64> = schema
        .fields()
        .iter()
        .map(|f| (f.name().clone(), 0))
        .collect();
    let mut samples = Vec::new();
    sibilla_b_output::read(path, schema.clone(), |row| {
        rows += 1;
        *statuses
            .entry(
                row.get("extraction_status")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
                    .into(),
            )
            .or_default() += 1;
        *labels
            .entry(
                row.get("label")
                    .filter(|v| !v.is_null())
                    .map(Value::to_string)
                    .unwrap_or("unknown".into()),
            )
            .or_default() += 1;
        if let Some(code) = row.get("extraction_error_code").and_then(Value::as_str) {
            for reason in code.split('|') {
                *errors.entry(reason.into()).or_default() += 1;
            }
            if samples.len() < 5 {
                samples.push(json!({"sample_id":row.get("sample_id"),"error_code":code}));
            }
        }
        for (name, count) in &mut missing {
            if row.get(name).is_none_or(Value::is_null) {
                *count += 1;
            }
        }
        Ok(())
    })?;
    let report = json!({"rows":rows,"columns":schema.fields().len(),"statuses":statuses,"labels":labels,"errors":errors,"missing":missing,"sample_errors":samples});
    if as_json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }
    println!("Rows: {rows}\nColumns: {}", schema.fields().len());
    for (title, counts) in [
        ("Statuses", &statuses),
        ("Labels (0=benign, 1=malicious)", &labels),
        ("Error reasons", &errors),
    ] {
        println!("\n{title}:");
        for (key, count) in counts {
            println!("  {key}: {count}");
        }
    }
    println!("\nMissing values (all rows):");
    for (name, count) in &missing {
        if *count > 0 {
            println!("  {}: {count}/{rows}", display_name(name));
        }
    }
    if !samples.is_empty() {
        println!("\nSample errors (up to 5):");
        for sample in samples {
            println!("  {}: {}", sample["sample_id"], sample["error_code"]);
        }
    }
    if columns {
        println!("\nDisplay name -> exported name:");
        for field in schema.fields() {
            println!("  {} -> {}", display_name(field.name()), field.name());
        }
    }
    Ok(())
}
/// Shorten display labels without changing the versioned exported column names.
fn display_name(name: &str) -> &str {
    name.strip_prefix("extraction_common_features_")
        .or_else(|| name.strip_prefix("extraction_format_features_"))
        .unwrap_or(name)
}
