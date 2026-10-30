//! Versioned extraction contract. Labels and provenance are never extractor inputs.
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const SCHEMA_VERSION: &str = "pdf-v3";
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
    pub malware: Option<MalwareFeatures>,
    pub stream_mode: Option<String>,
    pub stream_decode_unsupported_filters: Option<String>,
    pub stream_decode_status: Option<String>,
    pub stream_decode_success_count: Option<usize>,
    pub stream_decode_unsupported_count: Option<usize>,
    pub stream_decode_error_count: Option<usize>,
    pub stream_decode_coverage_ratio: Option<f64>,
    pub supported_decoded_stream_size_mean: Option<f64>,
    pub supported_decoded_stream_size_min: Option<f64>,
    pub supported_decoded_stream_size_max: Option<f64>,
    pub supported_decoded_stream_size_std: Option<f64>,
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
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamMode {
    Structural,
    #[default]
    Decoded,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Limits {
    pub max_size_bytes: u64,
    pub max_decompressed_bytes: u64,
    pub timeout_seconds: u64,
    #[serde(default)]
    pub stream_mode: StreamMode,
}
impl Default for Limits {
    /// Return conservative default extraction resource limits.
    fn default() -> Self {
        Self {
            max_size_bytes: 64 * 1024 * 1024,
            max_decompressed_bytes: 128 * 1024 * 1024,
            timeout_seconds: 30,
            stream_mode: StreamMode::Decoded,
        }
    }
}
pub trait FormatExtractor {
    /// Return the stable file-format identifier.
    fn format_id(&self) -> &'static str;
    /// Return the version of the emitted feature schema.
    fn schema_version(&self) -> &'static str;
    /// Extract static format features from bytes under the supplied resource limits.
    fn extract(&self, bytes: &[u8], limits: Limits) -> Extraction;
}

/// Bounded static analysis; null measurements indicate incomplete or unattempted analysis.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct MalwareFeatures {
    pub structure_status: String,
    pub payload_status: String,
    pub reachable_objects: Option<u64>,
    pub unreachable_objects: Option<u64>,
    pub broken_references: Option<u64>,
    pub max_graph_depth: Option<u64>,
    pub action_count: Option<u64>,
    pub javascript_action_count: Option<u64>,
    pub document_open_javascript_count: Option<u64>,
    pub additional_javascript_count: Option<u64>,
    pub annotation_javascript_count: Option<u64>,
    pub form_javascript_count: Option<u64>,
    pub uri_action_count: Option<u64>,
    pub launch_action_count: Option<u64>,
    pub navigation_action_count: Option<u64>,
    pub action_linked_attachments: Option<u64>,
    pub javascript_count: Option<u64>,
    pub javascript_bytes: Option<u64>,
    pub javascript_suspicious_api_tokens: Option<u64>,
    pub javascript_escape_sequences: Option<u64>,
    pub javascript_long_strings: Option<u64>,
    pub attachment_count: Option<u64>,
    pub attachment_decoded_bytes: Option<u64>,
    pub attachment_pe_signatures: Option<u64>,
    pub attachment_elf_signatures: Option<u64>,
    pub attachment_pdf_signatures: Option<u64>,
    pub attachment_zip_signatures: Option<u64>,
    pub attachment_script_signatures: Option<u64>,
    pub attachment_max_decoded_bytes: Option<u64>,
    pub attachment_executable_signatures: Option<u64>,
    pub url_count: Option<u64>,
    pub url_ip_literal_count: Option<u64>,
    pub url_unusual_scheme_count: Option<u64>,
    pub url_max_length: Option<u64>,
    pub payload_attempted_count: Option<u64>,
    pub payload_decoded_count: Option<u64>,
    pub payload_failed_count: Option<u64>,
}
