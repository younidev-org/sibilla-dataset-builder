// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 younidev-org.

use serde_json::json;
use sibilla_b_dataset::projection::{ProjectionOptions, learn_projection};
use std::collections::BTreeMap;
/// Training-only cleanup ignores information that will appear in validation rows.
#[test]
fn training_cleanup_and_alias_collisions() {
    let mut options = ProjectionOptions {
        groups: vec!["common.entropy".into()],
        drop_all_null: true,
        ..Default::default()
    };
    options
        .aliases
        .insert("common.entropy_global".into(), "byte_entropy".into());
    let row = BTreeMap::from([(
        "extraction_common_features_entropy_global".into(),
        json!(3.0),
    )]);
    let projection = learn_projection(std::iter::once(Ok(row)), &options).unwrap();
    assert!(
        projection
            .columns
            .iter()
            .any(|c| c.output_name == "byte_entropy")
    );
    assert!(
        !projection
            .columns
            .iter()
            .any(|c| c.id == "common.entropy_block_mean")
    );
    options
        .aliases
        .insert("common.entropy_global".into(), "sample_id".into());
    assert!(learn_projection(std::iter::empty(), &options).is_err());
}
/// Alias names must not impersonate targets/quality columns, and cleanup must not inspect validation values.
#[test]
fn metadata_aliases_and_training_only_cleanup() {
    let mut options = ProjectionOptions {
        groups: vec!["common.entropy".into()],
        drop_constant: true,
        ..Default::default()
    };
    options
        .aliases
        .insert("common.entropy_global".into(), "label".into());
    assert!(
        sibilla_b_dataset::projection::validate(&options)
            .unwrap_err()
            .to_string()
            .contains("alias")
    );
    options.aliases.clear();
    let rows = [
        BTreeMap::from([
            (
                "extraction_common_features_entropy_global".into(),
                json!(3.0),
            ),
            (
                "extraction_common_features_entropy_block_mean".into(),
                json!(2.0),
            ),
        ]),
        BTreeMap::from([
            (
                "extraction_common_features_entropy_global".into(),
                json!(3.0),
            ),
            (
                "extraction_common_features_entropy_block_mean".into(),
                json!(4.0),
            ),
        ]),
    ];
    let p = learn_projection(rows.into_iter().map(Ok), &options).unwrap();
    assert!(!p.columns.iter().any(|c| c.id == "common.entropy_global"));
    assert!(
        p.columns
            .iter()
            .any(|c| c.id == "common.entropy_block_mean")
    );
    assert!(
        learn_projection(
            std::iter::empty(),
            &ProjectionOptions {
                drop_all_null: true,
                ..Default::default()
            }
        )
        .is_err()
    );
}
