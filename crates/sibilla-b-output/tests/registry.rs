// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 younidev-org.

use sibilla_b_output::registry::{FeatureRole, registry, validate_selection};
use std::collections::BTreeSet;
/// Every exported field has exactly one stable canonical identity and matching type.
#[test]
fn registry_is_exhaustive_and_unique() {
    let descriptors = registry().unwrap();
    let schema = sibilla_b_output::extraction_schema();
    assert_eq!(descriptors.len(), schema.fields().len());
    assert_eq!(
        descriptors
            .iter()
            .map(|d| &d.id)
            .collect::<BTreeSet<_>>()
            .len(),
        descriptors.len()
    );
    for d in &descriptors {
        assert_eq!(
            &d.data_type,
            schema
                .field_with_name(&d.exported_name)
                .unwrap()
                .data_type()
        );
        assert!(!d.missing.is_empty());
    }
    for name in ["sample_id", "label", "source_dataset", "extraction_status"] {
        assert_ne!(
            descriptors
                .iter()
                .find(|d| d.exported_name == name)
                .unwrap()
                .role,
            FeatureRole::Predictive
        );
    }
    assert_eq!(
        descriptors
            .iter()
            .find(|d| d.exported_name == "extraction_common_features_entropy_global")
            .unwrap()
            .id,
        "common.entropy_global"
    );
}
/// Typos and fields belonging to unimplemented formats are rejected before processing.
#[test]
fn unknown_groups_and_columns_fail() {
    assert!(
        validate_selection(
            &["pdf.javascript".into()],
            &["common.entropy_global".into()]
        )
        .is_ok()
    );
    assert!(validate_selection(&["pdf.typo".into()], &[]).is_err());
    assert!(validate_selection(&[], &["pe.imports".into()]).is_err());
}
