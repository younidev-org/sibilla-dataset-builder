// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 younidev-org.

//! Canonical column selection and training-only cleanup, independent of manifest data.
use anyhow::{Context, Result, bail};
use arrow_schema::{Field, Schema};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sibilla_b_output::{
    Row,
    registry::{FeatureRole, registry},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
/// Model-facing projection; defaults preserve all predictive columns for legacy commands.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProjectionOptions {
    pub groups: Vec<String>,
    pub exclude: Vec<String>,
    pub aliases: BTreeMap<String, String>,
    pub drop_all_null: bool,
    pub drop_constant: bool,
}
/// One canonical feature and its exported alias, with interpretation and original field name.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectedColumn {
    pub id: String,
    pub input_name: String,
    pub output_name: String,
    pub unit: String,
    pub missing: String,
}
/// Learned training-only projection applied unchanged to all dataset rows.
pub struct ResolvedProjection {
    pub columns: Vec<ProjectedColumn>,
    pub dropped: BTreeMap<String, String>,
}
impl ResolvedProjection {
    /// Construct a nullable Arrow schema preserving the original scalar types and identity key.
    pub fn schema(&self) -> Result<Arc<Schema>> {
        let original = sibilla_b_output::extraction_schema();
        let mut fields = vec![original.field_with_name("sample_id")?.clone()];
        for c in &self.columns {
            fields.push(Field::new(
                &c.output_name,
                original.field_with_name(&c.input_name)?.data_type().clone(),
                true,
            ));
        }
        Ok(Arc::new(Schema::new(fields)))
    }
    /// Copy only selected values under aliases; never modify the manifest row.
    pub fn row(&self, row: Row) -> Row {
        let mut out = Row::from([(
            "sample_id".into(),
            row.get("sample_id").cloned().unwrap_or(Value::Null),
        )]);
        for c in &self.columns {
            out.insert(
                c.output_name.clone(),
                row.get(&c.input_name).cloned().unwrap_or(Value::Null),
            );
        }
        out
    }
    /// Record reversible names and why training cleanup removed other selected columns.
    pub fn metadata(&self) -> Value {
        json!({"columns":self.columns,"dropped":self.dropped,"identity_column":"sample_id"})
    }
}
/// Validate canonical references before observing rows or creating any output.
pub fn validate(options: &ProjectionOptions) -> Result<()> {
    sibilla_b_output::registry::validate_selection(&options.groups, &options.exclude)?;
    sibilla_b_output::registry::validate_selection(
        &[],
        &options.aliases.keys().cloned().collect::<Vec<_>>(),
    )?;
    let descriptors = registry()?;
    for id in &options.exclude {
        if descriptors
            .iter()
            .any(|d| &d.id == id && d.role != FeatureRole::Predictive)
        {
            bail!("cannot exclude mandatory identity or nonpredictive metadata: {id}");
        }
    }
    let selected = selected(options)?;
    let mut names: BTreeSet<String> = registry()?
        .into_iter()
        .filter(|d| d.role != FeatureRole::Predictive)
        .map(|d| d.exported_name)
        .collect();
    for c in &selected {
        if c.output_name.trim().is_empty() || !names.insert(c.output_name.clone()) {
            bail!("empty or duplicate feature alias: {}", c.output_name);
        }
    }
    for id in options.aliases.keys() {
        if !selected.iter().any(|c| &c.id == id) {
            bail!("alias refers to an excluded or nonpredictive feature: {id}");
        }
    }
    if selected.is_empty() {
        bail!("no selected feature columns");
    }
    Ok(())
}
/// Select registered predictive roles, preserving deterministic original schema ordering.
fn selected(options: &ProjectionOptions) -> Result<Vec<ProjectedColumn>> {
    Ok(registry()?
        .into_iter()
        .filter(|d| {
            d.role == FeatureRole::Predictive
                && (options.groups.is_empty() || options.groups.contains(&d.group))
                && !options.exclude.contains(&d.id)
        })
        .map(|d| ProjectedColumn {
            output_name: options
                .aliases
                .get(&d.id)
                .cloned()
                .unwrap_or_else(|| d.exported_name.clone()),
            id: d.id,
            input_name: d.exported_name,
            unit: d.unit,
            missing: d.missing,
        })
        .collect())
}
/// Fit all-null/non-null-constant removal using training rows exclusively; no imputation.
pub fn learn_projection(
    training_rows: impl Iterator<Item = Result<Row>>,
    options: &ProjectionOptions,
) -> Result<ResolvedProjection> {
    validate(options)?;
    let mut columns = selected(options)?;
    let mut dropped = BTreeMap::new();
    if options.drop_all_null || options.drop_constant {
        let mut count = 0;
        let mut values: BTreeMap<String, (Option<Value>, bool)> = columns
            .iter()
            .map(|c| (c.id.clone(), (None, false)))
            .collect();
        for row in training_rows {
            let row = row?;
            count += 1;
            for c in &columns {
                let v = row.get(&c.input_name).unwrap_or(&Value::Null);
                if v.is_null() {
                    continue;
                }
                let state = values.get_mut(&c.id).context("projection state")?;
                if let Some(first) = &state.0 {
                    state.1 |= first != v;
                } else {
                    state.0 = Some(v.clone());
                }
            }
        }
        if count == 0 {
            bail!("training rows are required for column cleanup");
        }
        columns.retain(|c| {
            let state = &values[&c.id];
            let reason = if options.drop_all_null && state.0.is_none() {
                Some("all_null_in_training")
            } else if options.drop_constant && state.0.is_some() && !state.1 {
                Some("constant_in_training")
            } else {
                None
            };
            if let Some(reason) = reason {
                dropped.insert(c.id.clone(), reason.into());
                false
            } else {
                true
            }
        });
    }
    if columns.is_empty() {
        bail!("training cleanup removed all feature columns");
    }
    Ok(ResolvedProjection { columns, dropped })
}
