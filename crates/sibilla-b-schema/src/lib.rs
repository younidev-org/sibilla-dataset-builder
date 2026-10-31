// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 younidev-org.

//! Versioned records shared by extraction workers, table writers, and dataset builders.
//!
//! Labels and provenance are supplied by the caller, never inferred by an extractor.
//! Optional measurements distinguish unavailable values (`None`) from measured zeros.
//! Coverage/status fields describe analysis completeness, not a malware verdict.
//! Changing field types, meanings, or the exported column set requires a schema version bump.
pub mod profile;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Exported measurement contract; readers and builders reject incompatible tables.
pub const SCHEMA_VERSION: &str = "pdf-v5";
/// Whole-file byte measurements, available independently of successful PDF parsing.
/// Ratios are fractions in 0..=1; entropy uses bits per byte.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CommonFeatures {
    /// Lowercase SHA-256 of the complete input; an identity/join key, not a predictive feature.
    pub sha256: String,
    /// Length of the original input in bytes.
    pub size_bytes: u64,
    /// Whole-file Shannon entropy in bits per byte (0..=8).
    pub entropy_global: f64,
    /// Mean entropy of 4096-byte blocks, including a final short block.
    pub entropy_block_mean: f64,
    /// Minimum block entropy in bits per byte.
    pub entropy_block_min: f64,
    /// Maximum block entropy in bits per byte.
    pub entropy_block_max: f64,
    /// Population standard deviation of block entropy.
    pub entropy_block_std: f64,
    /// Fraction of blocks whose entropy is strictly greater than 7.5 bits per byte.
    pub high_entropy_block_ratio: f64,
    /// Fraction of input bytes equal to zero.
    pub zero_byte_ratio: f64,
    /// Fraction of bytes in 0..=127.
    pub ascii_ratio: f64,
    /// Fraction of bytes in 32..=126.
    pub printable_ratio: f64,
    /// 256 normalized byte frequencies in decimal byte-value order; empty input yields zeros.
    pub byte_histogram: Vec<f64>,
}
/// PDF measurements grouped by analysis stage and stream role.
///
/// `None` means unavailable or not attempted. Image-only streams may be intentionally
/// skipped by general decoding while optional image analysis still decodes their pixels.
/// Nested groups flatten into scalar columns under `extraction_format_features_`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct PdfFeatures {
    /// Independent image metadata and optional JPEG measurements; absent when parsing is unavailable.
    pub images: Option<ImageFeatures>,
    /// Requested JPEG-analysis policy; builders require matching policies across inputs.
    pub image_decode_enabled: Option<bool>,
    /// Loaded streams declaring Subtype Image; this declaration does not establish safety.
    pub declared_image_stream_count: Option<usize>,
    /// Loaded indirect streams referenced through JS entries, including unreachable dictionaries.
    pub javascript_stream_count: Option<usize>,
    /// Loaded indirect streams declared EmbeddedFile or referenced through EF dictionaries.
    pub attachment_stream_count: Option<usize>,
    /// Loaded streams with no recognized image, script, or attachment role.
    pub unknown_stream_count: Option<usize>,
    /// Loaded streams assigned more than one role; these are not skipped as image-only.
    pub overlapping_stream_role_count: Option<usize>,
    /// Image-only streams intentionally skipped by general decoding; zero in structural mode.
    pub image_stream_decode_skipped_count: Option<usize>,

    /// Bounded graph, trigger-context, URL, script, and attachment analysis.
    pub malware: Option<MalwareFeatures>,
    /// Requested general measurement mode: structural or decoded.
    pub stream_mode: Option<String>,
    /// Sorted, pipe-separated unsupported filter names; null when decoding is not attempted.
    pub stream_decode_unsupported_filters: Option<String>,
    /// General decoding coverage: unavailable, not_attempted, complete, partial, or images_not_attempted.
    pub stream_decode_status: Option<String>,
    /// Number of loaded streams successfully decoded by general measurements.
    pub stream_decode_success_count: Option<usize>,
    /// Number of general stream attempts blocked by unsupported filters.
    pub stream_decode_unsupported_count: Option<usize>,
    /// Other general stream failures, including invalid filter declarations and budget exhaustion.
    pub stream_decode_error_count: Option<usize>,
    /// Successfully decoded streams divided by all loaded streams; 1 for an empty stream set.
    pub stream_decode_coverage_ratio: Option<f64>,
    /// Arithmetic mean over the successfully decoded subset only (bytes).
    pub supported_decoded_stream_size_mean: Option<f64>,
    /// Minimum over the successfully decoded subset only (bytes).
    pub supported_decoded_stream_size_min: Option<f64>,
    /// Maximum over the successfully decoded subset only (bytes).
    pub supported_decoded_stream_size_max: Option<f64>,
    /// Population standard deviation over the successfully decoded subset only (bytes).
    pub supported_decoded_stream_size_std: Option<f64>,
    /// Byte offset of the first PDF header, required to be within the first 1024 bytes.
    pub header_offset: Option<usize>,
    /// Three-character version text following the detected PDF header.
    pub version: Option<String>,
    /// Raw occurrences of the %%EOF marker, including occurrences inside stream data.
    pub eof_count: usize,
    /// Whether the last non-whitespace bytes end with %%EOF.
    pub trailing_eof: bool,
    /// Whether raw bytes contain /Linearized; not a validation of linearization.
    pub linearized: bool,
    /// Number of pages enumerated from the loaded page tree.
    pub page_count: Option<usize>,
    /// Number of objects retained by the parser, not all historical object definitions.
    pub object_count: Option<usize>,
    /// Loaded stream-object count, including cross-reference streams.
    pub stream_count: Option<usize>,
    /// Whether the document remains encrypted or was decrypted during loading.
    pub encrypted: Option<bool>,
    /// Raw /name substring counts; strings, comments, and encoded data can contribute.
    pub raw_tokens: BTreeMap<String, usize>,
    /// Name-object counts across loaded objects; null if the bounded traversal is incomplete.
    pub parsed_names: Option<BTreeMap<String, usize>>,
    /// Reference occurrences across loaded objects; null on traversal exhaustion.
    pub reference_count: Option<usize>,
    /// Unavailable: the loaded document does not preserve the historical table count.
    pub xref_table_count: Option<usize>,
    /// Loaded objects explicitly declaring Type XRef.
    pub xref_stream_count: Option<usize>,
    /// Loaded objects explicitly declaring Type ObjStm.
    pub object_stream_count: Option<usize>,
    /// Unavailable: duplicate historical definitions cannot be recovered from the loaded map.
    pub duplicate_object_ids: Option<usize>,
    /// Unavailable legacy measurement; use bounded graph diagnostics instead.
    pub inaccessible_objects: Option<usize>,
    /// Loaded objects explicitly declaring Type EmbeddedFile.
    pub embedded_file_count: Option<usize>,
    /// Loaded objects explicitly declaring Type Filespec.
    pub filespec_count: Option<usize>,
    /// Unavailable legacy total; use context-specific action counts in malware.
    pub document_javascript_action_count: Option<usize>,
    /// Presence count of catalog OpenAction and AA entries (0..=2), not executed actions.
    pub catalog_action_reference_count: Option<usize>,
    /// URI string entries found by the bounded loaded-object traversal.
    pub external_uri_count: Option<usize>,
    /// Distinct parsed URL host strings among discovered URI values.
    pub external_host_count: Option<usize>,
    /// Number of declared filter chains longer than three filters; a heuristic only.
    pub suspicious_filter_chain_count: Option<usize>,
    /// Arithmetic mean over all loaded encoded streams (bytes).
    pub raw_stream_size_mean: Option<f64>,
    /// Minimum over all loaded encoded streams (bytes).
    pub raw_stream_size_min: Option<f64>,
    /// Maximum over all loaded encoded streams (bytes).
    pub raw_stream_size_max: Option<f64>,
    /// Population standard deviation over all loaded encoded streams (bytes).
    pub raw_stream_size_std: Option<f64>,
    /// Arithmetic mean over all loaded decoded streams; null unless coverage is complete (bytes).
    pub decoded_stream_size_mean: Option<f64>,
    /// Minimum over all loaded decoded streams; null unless coverage is complete (bytes).
    pub decoded_stream_size_min: Option<f64>,
    /// Maximum over all loaded decoded streams; null unless coverage is complete (bytes).
    pub decoded_stream_size_max: Option<f64>,
    /// Population standard deviation over all loaded decoded streams; null unless coverage is complete (bytes).
    pub decoded_stream_size_std: Option<f64>,
    /// Arithmetic mean over declared filter-chain lengths; null if any declaration is invalid.
    pub filter_depth_mean: Option<f64>,
    /// Minimum over declared filter-chain lengths; null if any declaration is invalid.
    pub filter_depth_min: Option<f64>,
    /// Maximum over declared filter-chain lengths; null if any declaration is invalid.
    pub filter_depth_max: Option<f64>,
    /// Population standard deviation over declared filter-chain lengths; null if any declaration is invalid.
    pub filter_depth_std: Option<f64>,
    /// Fraction of all streams above 7.5 decoded bits/byte; null without full decoding coverage.
    pub high_entropy_stream_ratio: Option<f64>,
    /// Whether the loaded document exposes a catalog dictionary.
    pub catalog_present: Option<bool>,
    /// Whether the catalog declares Metadata; null when the catalog is unavailable.
    pub metadata_present: Option<bool>,
    /// Whether the catalog declares AcroForm; null when the catalog is unavailable.
    pub acroform_present: Option<bool>,
    /// Raw /Prev substring count, not a reconstruction of revision history.
    pub incremental_update_raw_count: usize,
    /// Raw #XX hexadecimal escape candidates, potentially including non-name data.
    pub encoded_name_raw_count: usize,
    /// Declared filter-name occurrences; unrecognized names aggregate under other.
    pub filter_counts: Option<BTreeMap<String, usize>>,
}
/// Overall extraction outcome; independent stage coverage can provide finer detail.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// No top-level extraction error; independent stage statuses still determine coverage.
    Success,
    /// Recoverable measurements exist, but at least one requested stage is incomplete.
    Partial,
    /// Worker failure prevented a usable extraction result.
    Failed,
    /// The coordinator stopped a worker after its allotted wall time.
    Timeout,
    /// Input was refused by file, format, size, or read validation.
    Rejected,
}
/// Measurements returned by a worker, including any recoverable partial results.
/// A worker failure can prevent even whole-file statistics from being returned.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Extraction {
    /// Whole-file statistics, absent when the worker could not return them.
    pub common_features: Option<CommonFeatures>,
    /// Format measurements; individual fields can remain unavailable after partial parsing.
    pub format_features: Option<PdfFeatures>,
    /// Overall outcome; consult individual stage coverage as well.
    pub status: Status,
    /// Optional sorted pipe-separated extraction reasons; detailed analysis reasons live in malware.
    pub error_code: Option<String>,
}
/// One discovered input with caller-supplied labels, provenance, and extraction results.
/// Records may include rejected or failed inputs; dataset assembly filters usability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Record {
    /// Optional lowercase SHA-256 identity linking manifests, features, and split tables.
    pub sample_id: Option<String>,
    /// Caller-supplied class: 0 benign, 1 malicious, None unknown.
    pub label: Option<u8>,
    /// Stable format identifier, currently pdf.
    pub file_format: String,
    /// Version of exported feature meanings and columns.
    pub feature_schema_version: String,
    /// Package version used to extract this record.
    pub extractor_version: String,
    /// Original source path relative to the extraction input, when available.
    pub original_relative_path: Option<String>,
    /// Optional caller-supplied source provenance; exclude from predictive inputs.
    pub source_dataset: Option<String>,
    /// Optional related-sample grouping identifier for leakage-aware splitting.
    pub collection_id: Option<String>,
    /// Observed worker elapsed time in milliseconds; not a predictive feature.
    pub extraction_duration_ms: u64,
    /// Worker result and recoverable measurements.
    pub extraction: Extraction,
}
/// Controls optional stream and payload analysis, not parser-internal decompression.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamMode {
    /// Measure bytes and structure without optional stream/payload decoding.
    Structural,
    /// Attempt bounded general-stream and relevant script/attachment decoding.
    #[default]
    Decoded,
}
/// Per-job limits passed into the restricted worker.
///
/// The decoded-byte budget is independent for general stream measurements, targeted
/// payloads, and optional image analysis; it is not a whole-process memory ceiling.
/// Worker OS memory restrictions remain separate.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Limits {
    /// Maximum original file size accepted by the extractor, in bytes.
    pub max_size_bytes: u64,
    /// Decoded-output allowance per analysis stage, in bytes; not total process memory.
    pub max_decompressed_bytes: u64,
    /// Positive wall-clock timeout enforced by the coordinator; worker CPU limits also apply.
    pub timeout_seconds: u64,
    #[serde(default)]
    /// Whether optional general-stream and targeted payload decoding is requested.
    pub stream_mode: StreamMode,
    #[serde(default)]
    /// Opt into the separate bounded JPEG stage; the CLI requires decoded mode.
    pub decode_images: bool,
}
impl Default for Limits {
    /// Return conservative default extraction resource limits.
    fn default() -> Self {
        Self {
            max_size_bytes: 64 * 1024 * 1024,
            max_decompressed_bytes: 128 * 1024 * 1024,
            timeout_seconds: 30,
            stream_mode: StreamMode::Decoded,
            decode_images: false,
        }
    }
}
/// Static format-specific extraction invoked inside an OS-restricted worker.
/// Implementations must not execute document content or perform network requests.
pub trait FormatExtractor {
    /// Return the stable file-format identifier.
    fn format_id(&self) -> &'static str;
    /// Return the version of the emitted feature schema.
    fn schema_version(&self) -> &'static str;
    /// Extract static format features from bytes under the supplied resource limits.
    fn extract(&self, bytes: &[u8], limits: Limits) -> Extraction {
        self.extract_selected(bytes, limits, &profile::FeatureSelection::default())
    }
    /// Extract only validated requested groups; identity and input checks remain mandatory.
    fn extract_selected(
        &self,
        bytes: &[u8],
        limits: Limits,
        selection: &profile::FeatureSelection,
    ) -> Extraction;
}

/// Bounded static analysis; null measurements indicate incomplete or unattempted analysis.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct MalwareFeatures {
    /// complete or partial for bounded graph/action traversal; missing references can still be counted.
    pub structure_status: String,
    /// complete, partial, or not_attempted for targeted script and attachment decoding.
    pub payload_status: String,
    /// Sorted pipe-separated analysis diagnostic codes; empty when no limitation was recorded.
    pub failure_reasons: String,
    /// JavaScript action relationships from primary annotation A entries, separate from event AA entries.
    pub annotation_primary_javascript_count: Option<u64>,
    /// JavaScript action relationships reached from page-level additional events.
    pub page_event_javascript_count: Option<u64>,
    /// JavaScript action relationships reached from catalog additional events.
    pub document_event_javascript_count: Option<u64>,

    /// Recognized PDF/EXE/DLL/ZIP filename extensions disagreeing with decoded leading bytes.
    pub attachment_type_mismatch_count: Option<u64>,
    /// Loaded indirect objects reachable from trailer values.
    pub reachable_objects: Option<u64>,
    /// Loaded indirect objects not reached from the trailer; not inherently suspicious.
    pub unreachable_objects: Option<u64>,
    /// Distinct missing target identities encountered during graph traversal.
    pub broken_references: Option<u64>,
    /// Maximum depth observed by the visited-set traversal, not a shortest-path graph distance.
    pub max_graph_depth: Option<u64>,
    /// Action relationships reached from known triggers; shared targets can count in multiple contexts.
    pub action_count: Option<u64>,
    /// JavaScript action relationships reached from known triggers, including Next chains.
    pub javascript_action_count: Option<u64>,
    /// JavaScript reached through catalog OpenAction chains.
    pub document_open_javascript_count: Option<u64>,
    /// JavaScript relationships reached from page/catalog additional events.
    pub additional_javascript_count: Option<u64>,
    /// JavaScript relationships from annotation primary actions or additional events.
    pub annotation_javascript_count: Option<u64>,
    /// JavaScript relationships from form primary actions or additional events.
    pub form_javascript_count: Option<u64>,
    /// Triggered action relationships declaring S URI.
    pub uri_action_count: Option<u64>,
    /// Triggered action relationships declaring S Launch.
    pub launch_action_count: Option<u64>,
    /// Triggered GoTo, GoToR, GoToE, or Named action relationships.
    pub navigation_action_count: Option<u64>,
    /// Action F entries resolving to file specifications containing EF.
    pub action_linked_attachments: Option<u64>,
    /// Reachable JavaScript action dictionaries carrying JS entries, independent of decoding.
    pub javascript_count: Option<u64>,
    /// Total successfully decoded script payload bytes before UTF-16 normalization.
    pub javascript_bytes: Option<u64>,
    /// Case-sensitive substring occurrences of the documented API-token list; no syntax analysis.
    pub javascript_suspicious_api_tokens: Option<u64>,
    /// Occurrences of backslash-x, backslash-u, and percent-u lexical sequences.
    pub javascript_escape_sequences: Option<u64>,
    /// Closed single/double quoted lexical runs of at least 256 bytes after normalization.
    pub javascript_long_strings: Option<u64>,
    /// Reachable EF entries; aliases to one indirect target within a single EF dictionary count once.
    pub attachment_count: Option<u64>,
    /// Total decoded attachment bytes; null if any targeted payload is incomplete.
    pub attachment_decoded_bytes: Option<u64>,
    /// Decoded attachments matching the leading MZ signature; no recursive validation.
    pub attachment_pe_signatures: Option<u64>,
    /// Decoded attachments matching the leading ELF signature; no recursive validation.
    pub attachment_elf_signatures: Option<u64>,
    /// Decoded attachments matching the leading %PDF- signature; no recursive validation.
    pub attachment_pdf_signatures: Option<u64>,
    /// Decoded attachments matching the leading PK local-file header signature; no recursive validation.
    pub attachment_zip_signatures: Option<u64>,
    /// Decoded attachments matching the leading shebang signature; no recursive validation.
    pub attachment_script_signatures: Option<u64>,
    /// Largest decoded attachment payload in bytes.
    pub attachment_max_decoded_bytes: Option<u64>,
    /// Leading MZ, ELF, shebang, or common Mach-O signatures; not executable validation.
    pub attachment_executable_signatures: Option<u64>,
    /// Reachable URI string entries; repeated values are counted separately.
    pub url_count: Option<u64>,
    /// URI entries parsed with literal IPv4 or IPv6 hosts.
    pub url_ip_literal_count: Option<u64>,
    /// URI entries outside http/https/mailto, including unparseable values.
    pub url_unusual_scheme_count: Option<u64>,
    /// Maximum stored URI-string length in bytes; no network lookup is performed.
    pub url_max_length: Option<u64>,
    /// Targeted script/attachment decode attempts; null when decoding is disabled or traversal incomplete.
    pub payload_attempted_count: Option<u64>,
    /// Successful targeted payload decodes, not an assertion of payload safety.
    pub payload_decoded_count: Option<u64>,
    /// Failed targeted payload decodes, including type, reference, codec, data, or budget errors.
    pub payload_failed_count: Option<u64>,
}

/// Declared image metadata and independently bounded optional JPEG decoding.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ImageFeatures {
    /// Images declaring DeviceGray or CalGray color-space families.
    pub grayscale_count: Option<u64>,
    /// Images declaring DeviceRGB or CalRGB color-space families.
    pub rgb_count: Option<u64>,
    /// Images declaring DeviceCMYK.
    pub cmyk_count: Option<u64>,
    /// Other, absent, or unrecognized color spaces; profile contents are not interpreted.
    pub other_color_space_count: Option<u64>,
    /// Maximum positive declared bit depth; zero if absent from every image.
    pub max_bits_per_component: Option<u64>,
    /// Images whose direct ImageMask value is true.
    pub image_mask_count: Option<u64>,

    /// not_attempted, complete, or partial for the independent optional JPEG stage.
    pub decode_status: String,
    /// Loaded streams declaring Subtype Image, regardless of role overlap.
    pub image_count: Option<u64>,
    /// Images missing positive dimensions or supported bit depth; JPX may omit bit depth.
    pub invalid_parameters_count: Option<u64>,
    /// Total stored bytes across declared image streams, before filter decoding.
    pub encoded_bytes: Option<u64>,
    /// Largest positive declared Width in pixels; zero if none is available.
    pub max_declared_width: Option<u64>,
    /// Largest positive declared Height in pixels; zero if none is available.
    pub max_declared_height: Option<u64>,
    /// JPEG images decoded successfully; null when optional image decoding is disabled.
    pub decoded_count: Option<u64>,
    /// Total pixel-buffer bytes from successful JPEG decodes only.
    pub decoded_bytes: Option<u64>,
    /// Maximum successful JPEG-header width in pixels; zero when no decode succeeds.
    pub max_decoded_width: Option<u64>,
    /// Maximum successful JPEG-header height in pixels; zero when no decode succeeds.
    pub max_decoded_height: Option<u64>,
    /// Successful JPEGs whose header dimensions differ from PDF declarations.
    pub dimension_mismatch_count: Option<u64>,
    /// Image attempts lacking a supported terminal DCT filter or supported filter prefix.
    pub unsupported_count: Option<u64>,
    /// Other image reference/decoder rejections, including unsupported JPEG variants; not proof of corruption.
    pub invalid_data_count: Option<u64>,
    /// Image attempts rejected by the shared image-stage decoded-byte budget.
    pub budget_exceeded_count: Option<u64>,
}
