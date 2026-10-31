// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 younidev-org.

//! Canonical feature identities and semantic annotations over the existing typed schema.
use anyhow::{Context, Result, bail};
use arrow_schema::DataType;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
/// Semantic role determines whether a column may enter the predictive feature export.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeatureRole {
    Predictive,
    Identity,
    Label,
    Metadata,
    Quality,
}
/// Canonical identity and interpretation; Arrow types come from the typed record template.
#[derive(Debug, Clone)]
pub struct FeatureDescriptor {
    pub id: String,
    pub exported_name: String,
    pub data_type: DataType,
    pub role: FeatureRole,
    pub group: String,
    pub unit: String,
    pub missing: String,
}
#[derive(Deserialize)]
struct Annotation {
    group: String,
    role: FeatureRole,
    unit: String,
    missing: String,
}
/// Resolve scalar fields and declared families, rejecting any missing or stale annotation.
pub fn registry() -> Result<Vec<FeatureDescriptor>> {
    let annotations: BTreeMap<String, Annotation> =
        serde_json::from_str(include_str!("registry_annotations.json"))?;
    let mut used = BTreeSet::new();
    let mut result = Vec::new();
    for f in crate::extraction_schema().fields() {
        let name = f.name();
        let family = if name.starts_with("extraction_common_features_byte_histogram_") {
            "extraction_common_features_byte_histogram_*".to_owned()
        } else if let Some(prefix) = [
            "extraction_format_features_filter_counts_",
            "extraction_format_features_raw_tokens_",
            "extraction_format_features_parsed_names_",
        ]
        .iter()
        .find(|p| name.starts_with(**p))
        {
            format!("{prefix}*")
        } else {
            name.clone()
        };
        let a = annotations
            .get(&family)
            .with_context(|| format!("missing feature annotation: {name}"))?;
        used.insert(family);
        let id = if let Some(s) = name.strip_prefix("extraction_common_features_") {
            format!("common.{s}")
        } else if let Some(s) = name.strip_prefix("extraction_format_features_") {
            format!("pdf.{s}")
        } else {
            format!("metadata.{name}")
        };
        result.push(FeatureDescriptor {
            id,
            exported_name: name.clone(),
            data_type: f.data_type().clone(),
            role: a.role.clone(),
            group: a.group.clone(),
            unit: a.unit.clone(),
            missing: a.missing.clone(),
        });
    }
    if used.len() != annotations.len() {
        bail!("stale feature registry annotation");
    }
    Ok(result)
}
/// Validate canonical group and column references without accepting arbitrary format names.
pub fn validate_selection(groups: &[String], ids: &[String]) -> Result<()> {
    for g in groups {
        if !sibilla_b_schema::profile::GROUPS.contains(&g.as_str()) {
            bail!("unknown feature group: {g}");
        }
    }
    let descriptors = registry()?;
    for id in ids {
        if !descriptors.iter().any(|d| &d.id == id) {
            bail!("unknown canonical feature: {id}");
        }
    }
    Ok(())
}
