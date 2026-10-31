// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 younidev-org.

//! Feature execution selection, independent of file paths, labels and resource limits.
use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
/// Stable feature-group identifiers; a future extractor adds its own format namespace.
pub const GROUPS: &[&str] = &[
    "common.size",
    "common.entropy",
    "common.byte_histogram",
    "pdf.structure",
    "pdf.actions",
    "pdf.javascript",
    "pdf.attachments",
    "pdf.links",
    "pdf.image_metadata",
    "pdf.stream_statistics",
];
/// Requested feature groups; empty means no optional measurements, not all groups.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeatureSelection {
    pub groups: BTreeSet<String>,
}
impl Default for FeatureSelection {
    /// Preserve existing inline extraction by enabling every currently supported group.
    fn default() -> Self {
        Self {
            groups: GROUPS.iter().map(|g| (*g).to_owned()).collect(),
        }
    }
}
impl FeatureSelection {
    /// Test whether an explicitly requested group is enabled.
    pub fn enabled(&self, group: &str) -> bool {
        self.groups.contains(group)
    }
    /// Reject unknown groups and unsatisfied execution dependencies before dispatch.
    pub fn validate(&self, decode_images: bool, structural: bool) -> Result<()> {
        for group in &self.groups {
            if !GROUPS.contains(&group.as_str()) {
                bail!("unknown feature group: {group}");
            }
        }
        if self.enabled("pdf.javascript") && !self.enabled("pdf.actions") {
            bail!("pdf.javascript requires pdf.actions");
        }
        if decode_images && (structural || !self.enabled("pdf.image_metadata")) {
            bail!("image decoding requires decoded mode and pdf.image_metadata");
        }
        Ok(())
    }
}
/// PDF execution profile; additional formats can add typed policies without replacing selection.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PdfProfile {
    pub selection: FeatureSelection,
    pub stream_mode: crate::StreamMode,
    pub decode_images: bool,
}
