//! Static parsing only. Call from a restricted subprocess, never the coordinator.
use lopdf::{Document, LoadOptions, Object};
use sibilla_b_schema::{Extraction, FormatExtractor, Limits, PdfFeatures, SCHEMA_VERSION, Status};
use std::collections::BTreeMap;
pub struct PdfExtractor;
const TOKENS: &[&str] = &[
    "JS",
    "JavaScript",
    "OpenAction",
    "AA",
    "Launch",
    "EmbeddedFile",
    "Filespec",
    "ObjStm",
    "XFA",
    "URI",
    "RichMedia",
    "AcroForm",
    "SubmitForm",
    "ImportData",
    "GoToR",
    "JBIG2Decode",
];
/// Count raw byte-substring occurrences without interpreting PDF syntax.
fn count(bytes: &[u8], token: &[u8]) -> usize {
    bytes.windows(token.len()).filter(|w| *w == token).count()
}
/// Count recognized parsed names, returning false when nesting exceeds the limit.
fn names(object: &Object, counts: &mut BTreeMap<String, usize>, depth: usize) -> bool {
    if depth > 64 {
        return false;
    }
    match object {
        Object::Name(name) => {
            if let Ok(key) = std::str::from_utf8(name)
                && let Some(n) = counts.get_mut(key)
            {
                *n += 1;
            }
            true
        }
        Object::Array(items) => items.iter().all(|item| names(item, counts, depth + 1)),
        Object::Dictionary(dict) => dict.iter().all(|(key, value)| {
            if let Ok(key) = std::str::from_utf8(key)
                && let Some(n) = counts.get_mut(key)
            {
                *n += 1;
            }
            names(value, counts, depth + 1)
        }),
        Object::Stream(stream) => {
            names(&Object::Dictionary(stream.dict.clone()), counts, depth + 1)
        }
        _ => true,
    }
}
impl FormatExtractor for PdfExtractor {
    /// Return the stable file-format identifier.
    fn format_id(&self) -> &'static str {
        "pdf"
    }
    /// Return the version of the emitted feature schema.
    fn schema_version(&self) -> &'static str {
        SCHEMA_VERSION
    }
    /// Extract static PDF indicators while preserving nulls for unavailable measurements.
    fn extract(&self, bytes: &[u8], limits: Limits) -> Extraction {
        if bytes.len() as u64 > limits.max_size_bytes {
            return Extraction {
                common_features: None,
                format_features: None,
                status: Status::Rejected,
                error_code: Some("size_limit".into()),
            };
        }
        let common = Some(sibilla_b_common_features::extract(bytes));
        let header = bytes.windows(5).position(|w| w == b"%PDF-");
        let Some(offset) = header.filter(|&o| o < 1024) else {
            return Extraction {
                common_features: common,
                format_features: None,
                status: Status::Rejected,
                error_code: Some("invalid_magic".into()),
            };
        };
        let mut features = PdfFeatures {
            header_offset: Some(offset),
            version: bytes
                .get(offset + 5..offset + 8)
                .and_then(|b| std::str::from_utf8(b).ok())
                .map(str::to_owned),
            eof_count: count(bytes, b"%%EOF"),
            trailing_eof: bytes
                .iter()
                .rposition(|b| !b.is_ascii_whitespace())
                .is_some_and(|end| bytes[..=end].ends_with(b"%%EOF")),
            linearized: count(bytes, b"/Linearized") > 0,
            page_count: None,
            object_count: None,
            stream_count: None,
            encrypted: None,
            raw_tokens: TOKENS
                .iter()
                .map(|t| (t.to_string(), count(bytes, format!("/{t}").as_bytes())))
                .collect(),
            parsed_names: None,
            incremental_update_raw_count: count(bytes, b"/Prev"),
            encoded_name_raw_count: encoded_names(bytes),
            ..PdfFeatures::default()
        };
        let options = LoadOptions::with_max_decompressed_size(
            limits.max_decompressed_bytes.min(usize::MAX as u64) as usize,
        );
        let (status, error_code) = match Document::load_mem_with_options(bytes, options) {
            Ok(doc) if doc.is_encrypted() => {
                features.encrypted = Some(true);
                (Status::Partial, Some("pdf_password_required".into()))
            }
            Ok(doc) => {
                let mut measurements_complete = measurements(&doc, &mut features, limits);
                features.encrypted = Some(doc.is_encrypted() || doc.was_encrypted());
                features.page_count = Some(doc.get_pages().len());
                features.object_count = Some(doc.objects.len());
                features.stream_count = Some(
                    doc.objects
                        .values()
                        .filter(|o| matches!(o, Object::Stream(_)))
                        .count(),
                );
                let mut counts = TOKENS.iter().map(|t| (t.to_string(), 0)).collect();
                if doc
                    .objects
                    .values()
                    .all(|object| names(object, &mut counts, 0))
                {
                    features.parsed_names = Some(counts);
                } else {
                    measurements_complete = false;
                }
                if measurements_complete {
                    (Status::Success, None)
                } else {
                    (
                        Status::Partial,
                        Some("stream_measurement_unavailable".into()),
                    )
                }
            }
            Err(_) => (Status::Partial, Some("pdf_parse_failed".into())),
        };
        Extraction {
            common_features: common,
            format_features: Some(features),
            status,
            error_code,
        }
    }
}

/// Count raw hexadecimal escape candidates in byte tokens.
fn encoded_names(bytes: &[u8]) -> usize {
    let mut total = 0;
    for token in bytes.split(|b| b.is_ascii_whitespace() || b"()<>[]{}/%".contains(b)) {
        total += token
            .windows(3)
            .filter(|w| w[0] == b'#' && w[1..].iter().all(u8::is_ascii_hexdigit))
            .count();
    }
    total
}
/// Compute population mean, minimum, maximum and standard deviation.
fn stats(values: &[f64]) -> (f64, f64, f64, f64) {
    let mean = values.iter().sum::<f64>() / values.len().max(1) as f64;
    (
        mean,
        values.iter().copied().reduce(f64::min).unwrap_or(0.0),
        values.iter().copied().reduce(f64::max).unwrap_or(0.0),
        (values.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / values.len().max(1) as f64)
            .sqrt(),
    )
}
/// Count references in loaded object values within the nesting limit.
fn references(object: &Object, depth: usize) -> Option<usize> {
    if depth > 64 {
        return None;
    }
    match object {
        Object::Reference(_) => Some(1),
        Object::Array(items) => items
            .iter()
            .try_fold(0, |n, v| Some(n + references(v, depth + 1)?)),
        Object::Dictionary(dict) => dict
            .iter()
            .try_fold(0, |n, (_, v)| Some(n + references(v, depth + 1)?)),
        Object::Stream(s) => s
            .dict
            .iter()
            .try_fold(0, |n, (_, v)| Some(n + references(v, depth + 1)?)),
        _ => Some(0),
    }
}
/// Collect URI strings from parsed objects without making network requests.
fn uris(object: &Object, depth: usize, urls: &mut Vec<String>) -> bool {
    if depth > 64 {
        return false;
    }
    match object {
        Object::Dictionary(dict) => {
            if let Ok(Object::String(bytes, _)) = dict.get(b"URI") {
                urls.push(String::from_utf8_lossy(bytes).into_owned());
            }
            dict.iter().all(|(_, v)| uris(v, depth + 1, urls))
        }
        Object::Array(items) => items.iter().all(|v| uris(v, depth + 1, urls)),
        Object::Stream(s) => s.dict.iter().all(|(_, v)| uris(v, depth + 1, urls)),
        _ => true,
    }
}
/// Populate available semantic and bounded stream measurements.
fn measurements(doc: &Document, features: &mut PdfFeatures, limits: Limits) -> bool {
    let catalog = doc.catalog().ok();
    features.catalog_present = Some(catalog.is_some());
    features.metadata_present = catalog.map(|c| c.has(b"Metadata"));
    features.acroform_present = catalog.map(|c| c.has(b"AcroForm"));
    features.reference_count = doc
        .objects
        .values()
        .try_fold(0, |n, o| Some(n + references(o, 0)?));
    let type_count = |name: &[u8]| {
        doc.objects
            .values()
            .filter(|o| o.type_name().is_ok_and(|n| n == name))
            .count()
    };
    features.object_stream_count = Some(type_count(b"ObjStm"));
    features.xref_stream_count = Some(type_count(b"XRef"));
    features.embedded_file_count = Some(type_count(b"EmbeddedFile"));
    features.filespec_count = Some(type_count(b"Filespec"));
    let mut raw = Vec::new();
    let mut decoded = Vec::new();
    let mut depths = Vec::new();
    let mut remaining = limits.max_decompressed_bytes.min(usize::MAX as u64) as usize;
    let mut complete = true;
    let mut high_entropy = 0;
    let mut filters: BTreeMap<String, usize> = [
        "ASCIIHexDecode",
        "ASCII85Decode",
        "LZWDecode",
        "FlateDecode",
        "RunLengthDecode",
        "CCITTFaxDecode",
        "JBIG2Decode",
        "DCTDecode",
        "JPXDecode",
        "Crypt",
        "other",
    ]
    .iter()
    .map(|s| (s.to_string(), 0))
    .collect();
    for object in doc.objects.values() {
        if let Object::Stream(stream) = object {
            raw.push(stream.content.len() as f64);
            match if stream.dict.has(b"Filter") {
                stream.filters()
            } else {
                Ok(Vec::new())
            } {
                Ok(chain) => {
                    depths.push(chain.len() as f64);
                    for filter in chain {
                        let name = std::str::from_utf8(filter).unwrap_or("other");
                        let key = if filters.contains_key(name) {
                            name
                        } else {
                            "other"
                        };
                        *filters.get_mut(key).expect("filter schema") += 1;
                    }
                }
                Err(_) => complete = false,
            }
            let identity =
                !stream.dict.has(b"Filter") || stream.filters().is_ok_and(|chain| chain.is_empty());
            let content = if identity {
                if stream.content.len() <= remaining {
                    Ok(stream.content.clone())
                } else {
                    Err(lopdf::Error::Syntax(
                        "stream exceeds remaining budget".into(),
                    ))
                }
            } else {
                stream.decompressed_content_with_limit(remaining)
            };
            match content {
                Ok(bytes) if bytes.len() <= remaining => {
                    remaining -= bytes.len();
                    decoded.push(bytes.len() as f64);
                    if sibilla_b_common_features::extract(&bytes).entropy_global > 7.5 {
                        high_entropy += 1;
                    }
                }
                _ => complete = false,
            }
        }
    }
    let (mean, min, max, std) = stats(&raw);
    features.raw_stream_size_mean = Some(mean);
    features.raw_stream_size_min = Some(min);
    features.raw_stream_size_max = Some(max);
    features.raw_stream_size_std = Some(std);
    if depths.len() == raw.len() {
        let (mean, min, max, std) = stats(&depths);
        features.filter_depth_mean = Some(mean);
        features.filter_depth_min = Some(min);
        features.filter_depth_max = Some(max);
        features.filter_depth_std = Some(std);
        features.suspicious_filter_chain_count = Some(depths.iter().filter(|&&d| d > 3.0).count());
        features.filter_counts = Some(filters);
    }
    if decoded.len() == raw.len() {
        let (mean, min, max, std) = stats(&decoded);
        features.decoded_stream_size_mean = Some(mean);
        features.decoded_stream_size_min = Some(min);
        features.decoded_stream_size_max = Some(max);
        features.decoded_stream_size_std = Some(std);
        features.high_entropy_stream_ratio = Some(high_entropy as f64 / raw.len().max(1) as f64);
    }
    let mut urls = Vec::new();
    if doc.objects.values().all(|o| uris(o, 0, &mut urls)) {
        features.external_uri_count = Some(urls.len());
        let hosts: std::collections::BTreeSet<_> = urls
            .iter()
            .filter_map(|s| url::Url::parse(s).ok())
            .filter_map(|u| u.host_str().map(str::to_owned))
            .collect();
        features.external_host_count = Some(hosts.len());
    }
    complete
}

#[cfg(test)]
mod tests {
    use sibilla_b_schema::{FormatExtractor, Limits, Status};
    /// Verify that an empty filter array preserves decoded stream bytes.
    #[test]
    fn empty_filter_array_is_identity() {
        let mut doc = lopdf::Document::new();
        doc.add_object(lopdf::Stream::new(
            lopdf::dictionary! {"Filter"=>Vec::<lopdf::Object>::new()},
            vec![42; 5],
        ));
        let mut features = sibilla_b_schema::PdfFeatures::default();
        assert!(super::measurements(&doc, &mut features, Limits::default()));
        assert_eq!(features.decoded_stream_size_mean, Some(5.0));
    }
    /// Verify encryption identity and null semantics for password-protected pages.
    #[test]
    fn encryption_does_not_turn_unavailable_pages_into_zero() {
        use lopdf::{EncryptionState, EncryptionVersion, Object, Permissions};
        for password in ["", "private"] {
            let mut doc = lopdf::Document::with_version("1.5");
            let root = doc.add_object(lopdf::dictionary! {"Type"=>"Catalog"});
            doc.trailer.set("Root", root);
            doc.trailer.set(
                "ID",
                Object::Array(vec![
                    Object::string_literal(vec![1; 16]),
                    Object::string_literal(vec![2; 16]),
                ]),
            );
            let state = EncryptionState::try_from(EncryptionVersion::V1 {
                document: &doc,
                owner_password: "owner",
                user_password: password,
                permissions: Permissions::all(),
            })
            .unwrap();
            doc.encrypt(&state).unwrap();
            let mut bytes = Vec::new();
            doc.save_to(&mut bytes).unwrap();
            let row = super::PdfExtractor.extract(&bytes, Limits::default());
            let features = row.format_features.unwrap();
            assert_eq!(features.encrypted, Some(true));
            if !password.is_empty() {
                assert_eq!(row.status, Status::Partial);
                assert!(features.page_count.is_none());
                assert!(features.parsed_names.is_none());
            }
        }
    }
    /// Verify bounded decoding, typed embeds and URI host measurements on generated PDFs.
    #[test]
    fn compressed_embeds_and_uris_are_static_measurements() {
        use lopdf::{Document, Stream, dictionary};
        let mut doc = Document::with_version("1.7");
        let pages = doc.add_object(
            dictionary! {"Type"=>"Pages","Count"=>0,"Kids"=>Vec::<lopdf::Object>::new()},
        );
        let embedded = doc.add_object(Stream::new(
            dictionary! {"Type"=>"EmbeddedFile"},
            vec![0; 100],
        ));
        doc.add_object(dictionary! {"Type"=>"Filespec","EF"=>dictionary! {"F"=>embedded}});
        doc.add_object(dictionary! {"S"=>"URI","URI"=>lopdf::Object::string_literal("https://example.invalid/a")});
        let root =
            doc.add_object(dictionary! {"Type"=>"Catalog","Pages"=>pages,"Metadata"=>embedded});
        doc.trailer.set("Root", root);
        doc.compress();
        let mut bytes = Vec::new();
        doc.save_to(&mut bytes).unwrap();
        let row = super::PdfExtractor.extract(&bytes, Limits::default());
        assert_eq!(row.status, Status::Success);
        let pdf = row.format_features.unwrap();
        assert_eq!(pdf.embedded_file_count, Some(1));
        assert_eq!(pdf.filespec_count, Some(1));
        assert_eq!(pdf.external_uri_count, Some(1));
        assert_eq!(pdf.external_host_count, Some(1));
        assert_eq!(pdf.decoded_stream_size_max, Some(100.0));
        assert_eq!(pdf.filter_depth_max, Some(1.0));
        let row = super::PdfExtractor.extract(
            &bytes,
            Limits {
                max_decompressed_bytes: 1,
                ..Limits::default()
            },
        );
        assert_eq!(row.status, Status::Partial);
        let pdf = row.format_features.unwrap();
        assert!(pdf.decoded_stream_size_mean.is_none());
    }
    /// Verify that parser failure preserves byte features and raw token counts.
    #[test]
    fn malformed_retains_bytes() {
        let row = super::PdfExtractor.extract(b"%PDF-1.7\n/JavaScript %%EOF", Limits::default());
        assert_eq!(row.status, Status::Partial);
        assert!(row.common_features.is_some());
        let pdf = row.format_features.unwrap();
        assert_eq!(pdf.raw_tokens["JavaScript"], 1);
        assert!(pdf.parsed_names.is_none());
    }
    /// Verify rejection of empty/non-PDF and oversized inputs without invented features.
    #[test]
    fn empty_and_oversized_rejected() {
        let row = super::PdfExtractor.extract(b"", Limits::default());
        assert_eq!(row.status, Status::Rejected);
        assert!(row.common_features.is_some());
        let limits = Limits {
            max_size_bytes: 1,
            ..Limits::default()
        };
        let row = super::PdfExtractor.extract(b"%PDF-1.7", limits);
        assert_eq!(row.status, Status::Rejected);
        assert!(row.common_features.is_none());
    }
    /// Verify that a generated safe PDF yields one parsed page.
    #[test]
    fn generated_pdf_parses() {
        let mut doc = lopdf::Document::with_version("1.7");
        let pages_id = doc.new_object_id();
        let page_id = doc.add_object(lopdf::dictionary! { "Type" => "Page", "Parent" => pages_id });
        doc.objects.insert(pages_id, lopdf::Object::Dictionary(lopdf::dictionary! { "Type" => "Pages", "Kids" => vec![page_id.into()], "Count" => 1 }));
        let root = doc.add_object(lopdf::dictionary! { "Type" => "Catalog", "Pages" => pages_id });
        doc.trailer.set("Root", root);
        let mut bytes = Vec::new();
        doc.save_to(&mut bytes).unwrap();
        let row = super::PdfExtractor.extract(&bytes, Limits::default());
        assert_eq!(row.status, Status::Success);
        assert_eq!(row.format_features.unwrap().page_count, Some(1));
    }
}
