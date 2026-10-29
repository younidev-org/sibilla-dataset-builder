//! Static parsing only. Call from a restricted subprocess, never the coordinator.
use lopdf::{Document, LoadOptions, Object};
use sibilla_schema::{Extraction, FormatExtractor, Limits, PdfFeatures, SCHEMA_VERSION, Status};
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
fn count(bytes: &[u8], token: &[u8]) -> usize {
    bytes.windows(token.len()).filter(|w| *w == token).count()
}
fn names(object: &Object, counts: &mut BTreeMap<String, usize>, depth: usize) {
    if depth > 64 {
        return;
    }
    match object {
        Object::Name(name) => {
            if let Ok(key) = std::str::from_utf8(name)
                && let Some(n) = counts.get_mut(key)
            {
                *n += 1;
            }
        }
        Object::Array(items) => {
            for item in items {
                names(item, counts, depth + 1);
            }
        }
        Object::Dictionary(dict) => {
            for (key, value) in dict.iter() {
                if let Ok(key) = std::str::from_utf8(key)
                    && let Some(n) = counts.get_mut(key)
                {
                    *n += 1;
                }
                names(value, counts, depth + 1);
            }
        }
        Object::Stream(stream) => {
            names(&Object::Dictionary(stream.dict.clone()), counts, depth + 1)
        }
        _ => {}
    }
}
impl FormatExtractor for PdfExtractor {
    fn format_id(&self) -> &'static str {
        "pdf"
    }
    fn schema_version(&self) -> &'static str {
        SCHEMA_VERSION
    }
    fn extract(&self, bytes: &[u8], limits: Limits) -> Extraction {
        if bytes.len() as u64 > limits.max_size_bytes {
            return Extraction {
                common_features: None,
                format_features: None,
                status: Status::Rejected,
                error_code: Some("size_limit".into()),
            };
        }
        let common = Some(sibilla_common_features::extract(bytes));
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
        };
        let options = LoadOptions::with_max_decompressed_size(
            limits.max_decompressed_bytes.min(usize::MAX as u64) as usize,
        );
        let (status, error_code) = match Document::load_mem_with_options(bytes, options) {
            Ok(doc) => {
                features.encrypted = Some(doc.is_encrypted());
                features.page_count = Some(doc.get_pages().len());
                features.object_count = Some(doc.objects.len());
                features.stream_count = Some(
                    doc.objects
                        .values()
                        .filter(|o| matches!(o, Object::Stream(_)))
                        .count(),
                );
                let mut counts = TOKENS.iter().map(|t| (t.to_string(), 0)).collect();
                for object in doc.objects.values() {
                    names(object, &mut counts, 0);
                }
                features.parsed_names = Some(counts);
                (Status::Success, None)
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

#[cfg(test)]
mod tests {
    use sibilla_schema::{FormatExtractor, Limits, Status};
    #[test]
    fn malformed_retains_bytes() {
        let row = super::PdfExtractor.extract(b"%PDF-1.7\n/JavaScript %%EOF", Limits::default());
        assert_eq!(row.status, Status::Partial);
        assert!(row.common_features.is_some());
        let pdf = row.format_features.unwrap();
        assert_eq!(pdf.raw_tokens["JavaScript"], 1);
        assert!(pdf.parsed_names.is_none());
    }
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
