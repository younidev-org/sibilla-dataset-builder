// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 younidev-org.

use anyhow::Result;
use serde_json::{Value, json};
use std::{collections::BTreeMap, path::Path};
/// Read every extraction row with bounded sample storage and report quality and missingness.
pub fn run(path: &Path, as_json: bool, columns: bool) -> Result<()> {
    let schema = sibilla_b_output::extraction_schema();
    let mut quality = sibilla_b_output::quality::QualitySummary::default();
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
    let mut modes = BTreeMap::<String, u64>::new();
    let mut decoding = BTreeMap::<String, u64>::new();
    let mut analysis_structure = BTreeMap::<String, u64>::new();
    let mut analysis_payloads = BTreeMap::<String, u64>::new();
    let mut images = BTreeMap::<String, u64>::new();
    let mut analysis_reasons = BTreeMap::<String, u64>::new();
    let mut unsupported_filters = BTreeMap::<String, u64>::new();
    sibilla_b_output::read(path, schema.clone(), |row| {
        quality.observe(&row)?;
        rows += 1;
        if let Some(reasons) = row
            .get("extraction_format_features_malware_failure_reasons")
            .and_then(Value::as_str)
        {
            for reason in reasons.split('|').filter(|r| !r.is_empty()) {
                *analysis_reasons.entry(reason.to_owned()).or_default() += 1;
            }
        }
        for (column, counts) in [
            (
                "extraction_format_features_images_decode_status",
                &mut images,
            ),
            (
                "extraction_format_features_malware_structure_status",
                &mut analysis_structure,
            ),
            (
                "extraction_format_features_malware_payload_status",
                &mut analysis_payloads,
            ),
            ("extraction_format_features_stream_mode", &mut modes),
            (
                "extraction_format_features_stream_decode_status",
                &mut decoding,
            ),
        ] {
            if let Some(value) = row.get(column).and_then(Value::as_str) {
                *counts.entry(value.to_owned()).or_default() += 1;
            }
        }
        if let Some(names) = row
            .get("extraction_format_features_stream_decode_unsupported_filters")
            .and_then(Value::as_str)
        {
            for name in names.split('|').filter(|name| !name.is_empty()) {
                *unsupported_filters.entry(name.to_owned()).or_default() += 1;
            }
        }
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
    let report = json!({"image_decode_statuses":images,"analysis_failure_reasons":analysis_reasons,"quality_by_label_source":quality.report(),"rows":rows,"columns":schema.fields().len(),"statuses":statuses,"labels":labels,"errors":errors,"missing":missing,"sample_errors":samples,"malware_structure_statuses":analysis_structure,"malware_payload_statuses":analysis_payloads,"stream_modes":modes,"stream_decode_statuses":decoding,"unsupported_filters_per_document":unsupported_filters});
    if as_json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }
    println!("Rows: {rows}\nColumns: {}", schema.fields().len());
    for (title, counts) in [
        ("Statuses", &statuses),
        ("Labels (0=benign, 1=malicious)", &labels),
        ("Error reasons", &errors),
        ("Analysis failure reasons", &analysis_reasons),
        ("Image decoding", &images),
        ("Malware structure analysis", &analysis_structure),
        ("Malware payload analysis", &analysis_payloads),
        ("Stream modes", &modes),
        ("Stream decoding", &decoding),
        ("Unsupported filters (documents)", &unsupported_filters),
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
    for group in quality.report().as_array().into_iter().flatten() {
        println!(
            "\nQuality: label={} source={} rows={} all-null={} constant={}",
            group["label"],
            group["source"],
            group["rows"],
            group["all_null_columns"].as_array().unwrap().len(),
            group["constant_non_null_columns"].as_array().unwrap().len()
        );
    }
    if columns {
        println!("\nDisplay name -> canonical ID -> exported name:");
        for descriptor in sibilla_b_output::registry::registry()? {
            println!(
                "  {} -> {} -> {}",
                display_name(&descriptor.exported_name),
                descriptor.id,
                descriptor.exported_name
            );
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
