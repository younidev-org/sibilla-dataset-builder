// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 younidev-org.

//! Quality reporting by caller-supplied label/source, independent of feature selection.
//!
//! Missing values and absent schema keys both contribute to missingness. Constant
//! means every observed non-null value is equal; a constant column can still have
//! missing values. All-null columns are reported separately, never as measured zeros.
//! Input and retained dataset rows use separate accumulators to expose selection effects.
use crate::Row;
use serde_json::{Value, json};
use std::collections::BTreeMap;
/// Accumulates schema-column quality for at most 128 distinct label/source groups.
///
/// Keeps counts and one representative non-null value per column, not all rows.
/// Tuple keys use JSON serialization to distinguish null provenance from literal strings.
#[derive(Default)]
pub struct QualitySummary {
    groups: BTreeMap<String, Group>,
    fields: Vec<String>,
}
#[derive(Default)]
struct Group {
    rows: usize,
    statuses: BTreeMap<String, usize>,
    errors: BTreeMap<String, usize>,
    /// Per column: missing count, first non-null value, and whether another value differs.
    columns: BTreeMap<String, (usize, Option<Value>, bool)>,
}
impl QualitySummary {
    /// Observe one row against the fixed extraction schema, including absent columns.
    ///
    /// `analysis:` prefixes detailed analysis reasons to distinguish them from
    /// top-level extraction reasons. Multiple reasons can apply to the same row.
    ///
    /// # Errors
    /// Returns an error before creating a 129th label/source group. Row validation
    /// remains the caller's responsibility; this accumulator does not assign labels.
    pub fn observe(&mut self, row: &Row) -> anyhow::Result<()> {
        let key = serde_json::to_string(&(row.get("label"), row.get("source_dataset")))?;
        if !self.groups.contains_key(&key) && self.groups.len() >= 128 {
            anyhow::bail!("quality report supports at most 128 label/source groups");
        }
        let group = self.groups.entry(key).or_default();
        group.rows += 1;
        *group
            .statuses
            .entry(
                row.get("extraction_status")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
                    .to_owned(),
            )
            .or_default() += 1;
        for (column, prefix) in [
            ("extraction_error_code", ""),
            (
                "extraction_format_features_malware_failure_reasons",
                "analysis:",
            ),
        ] {
            if let Some(reasons) = row.get(column).and_then(Value::as_str) {
                for reason in reasons.split('|').filter(|r| !r.is_empty()) {
                    *group.errors.entry(format!("{prefix}{reason}")).or_default() += 1;
                }
            }
        }
        if self.fields.is_empty() {
            self.fields = crate::extraction_schema()
                .fields()
                .iter()
                .map(|f| f.name().clone())
                .collect();
        }
        for name in &self.fields {
            let value = row.get(name).unwrap_or(&Value::Null);
            let state = group.columns.entry(name.clone()).or_default();
            if value.is_null() {
                state.0 += 1;
            } else if let Some(first) = &state.1 {
                if first != value {
                    state.2 = true;
                }
            } else {
                state.1 = Some(value.clone());
            }
        }
        Ok(())
    }
    /// Return deterministic JSON groups with statuses, reasons, missingness and constancy.
    ///
    /// Rates divide missing observations by group rows. Empty input returns an empty
    /// array; every existing group has at least one row, so no zero denominator arises.
    /// Report keys preserve source/label identity; they are not predictive features.
    pub fn report(&self) -> Value {
        Value::Array(self.groups.iter().map(|(key,g)| {
            let identity:Value=serde_json::from_str(key).expect("internally serialized group key");
            let missing:BTreeMap<_,_>=g.columns.iter().map(|(k,v)|(k,v.0)).collect();
            let rates:BTreeMap<_,_>=g.columns.iter().map(|(k,v)|(k,v.0 as f64/g.rows as f64)).collect();
            let all_null:Vec<_>=g.columns.iter().filter(|(_,v)|v.1.is_none()).map(|(k,_)|k).collect();
            let constant:Vec<_>=g.columns.iter().filter(|(_,v)|v.1.is_some()&&!v.2).map(|(k,_)|k).collect();
            json!({"label":identity[0],"source":identity[1],"rows":g.rows,"statuses":g.statuses,"error_reasons":g.errors,"missing_counts":missing,"missing_rates":rates,"all_null_columns":all_null,"constant_non_null_columns":constant})
        }).collect())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    /// Verify missing and constant fields are distinguished independently for each class/source.
    #[test]
    fn quality_groups_preserve_missingness() {
        let mut summary = QualitySummary::default();
        for value in [Value::Null, json!(3)] {
            summary
                .observe(&BTreeMap::from([
                    ("label".into(), json!(0)),
                    ("source_dataset".into(), json!("a")),
                    ("extraction_common_features_size_bytes".into(), value),
                ]))
                .unwrap();
        }
        summary
            .observe(&BTreeMap::from([
                ("label".into(), json!(1)),
                ("source_dataset".into(), json!("b")),
            ]))
            .unwrap();
        let report = summary.report();
        assert_eq!(report.as_array().unwrap().len(), 2);
        assert_eq!(
            report[0]["missing_counts"]["extraction_common_features_size_bytes"],
            1
        );
        assert!(
            report[1]["all_null_columns"]
                .as_array()
                .unwrap()
                .contains(&json!("extraction_common_features_size_bytes"))
        );
    }
}
