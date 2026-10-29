//! Versioned extraction contract. Labels and provenance are never extractor inputs.
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const SCHEMA_VERSION: &str = "pdf-v1";
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CommonFeatures {
    pub sha256: String,
    pub size_bytes: u64,
    pub entropy_global: f64,
    pub entropy_block_mean: f64,
    pub entropy_block_min: f64,
    pub entropy_block_max: f64,
    pub entropy_block_std: f64,
    pub high_entropy_block_ratio: f64,
    pub zero_byte_ratio: f64,
    pub ascii_ratio: f64,
    pub printable_ratio: f64,
    pub byte_histogram: Vec<f64>,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct PdfFeatures {
    pub header_offset: Option<usize>,
    pub version: Option<String>,
    pub eof_count: usize,
    pub trailing_eof: bool,
    pub linearized: bool,
    pub page_count: Option<usize>,
    pub object_count: Option<usize>,
    pub stream_count: Option<usize>,
    pub encrypted: Option<bool>,
    pub raw_tokens: BTreeMap<String, usize>,
    pub parsed_names: Option<BTreeMap<String, usize>>,
    pub reference_count: Option<usize>,
    pub xref_table_count: Option<usize>,
    pub xref_stream_count: Option<usize>,
    pub object_stream_count: Option<usize>,
    pub duplicate_object_ids: Option<usize>,
    pub inaccessible_objects: Option<usize>,
    pub embedded_file_count: Option<usize>,
    pub filespec_count: Option<usize>,
    pub document_javascript_action_count: Option<usize>,
    pub catalog_action_reference_count: Option<usize>,
    pub external_uri_count: Option<usize>,
    pub external_host_count: Option<usize>,
    pub suspicious_filter_chain_count: Option<usize>,
    pub raw_stream_size_mean: Option<f64>,
    pub raw_stream_size_min: Option<f64>,
    pub raw_stream_size_max: Option<f64>,
    pub raw_stream_size_std: Option<f64>,
    pub decoded_stream_size_mean: Option<f64>,
    pub decoded_stream_size_min: Option<f64>,
    pub decoded_stream_size_max: Option<f64>,
    pub decoded_stream_size_std: Option<f64>,
    pub filter_depth_mean: Option<f64>,
    pub filter_depth_min: Option<f64>,
    pub filter_depth_max: Option<f64>,
    pub filter_depth_std: Option<f64>,
    pub high_entropy_stream_ratio: Option<f64>,
    pub catalog_present: Option<bool>,
    pub metadata_present: Option<bool>,
    pub acroform_present: Option<bool>,
    pub incremental_update_raw_count: usize,
    pub encoded_name_raw_count: usize,
    pub filter_counts: Option<BTreeMap<String, usize>>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Success,
    Partial,
    Failed,
    Timeout,
    Rejected,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Extraction {
    pub common_features: Option<CommonFeatures>,
    pub format_features: Option<PdfFeatures>,
    pub status: Status,
    pub error_code: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Record {
    pub sample_id: Option<String>,
    pub label: Option<u8>,
    pub file_format: String,
    pub feature_schema_version: String,
    pub extractor_version: String,
    pub original_relative_path: Option<String>,
    pub source_dataset: Option<String>,
    pub collection_id: Option<String>,
    pub extraction_duration_ms: u64,
    pub extraction: Extraction,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Limits {
    pub max_size_bytes: u64,
    pub max_decompressed_bytes: u64,
    pub timeout_seconds: u64,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_size_bytes: 64 * 1024 * 1024,
            max_decompressed_bytes: 128 * 1024 * 1024,
            timeout_seconds: 30,
        }
    }
}
pub trait FormatExtractor {
    fn format_id(&self) -> &'static str;
    fn schema_version(&self) -> &'static str;
    fn extract(&self, bytes: &[u8], limits: Limits) -> Extraction;
}
