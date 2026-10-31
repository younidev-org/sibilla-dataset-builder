// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 younidev-org.

//! Conservative stream roles from declarations and references, without payload execution.
//!
//! Roles are flags: image = 1, JavaScript = 2, attachment = 4. Zero means unrecognized;
//! multiple flags preserve overlap rather than choosing a single supposedly safe role.
//! Scanning includes unreachable loaded objects, unlike action/payload analysis.
//! A role is a declared or syntactic relationship, not validation of the content.
use lopdf::{Document, Object, ObjectId};
use std::collections::BTreeMap;
/// Map loaded indirect stream identities to image/script/attachment role flags.
///
/// Scans at most 100,000 direct-object visits and 64 nesting levels. Indirect values
/// used for JS/EF targets are resolved with the document's bounded dereferencer.
/// Returns `None` on scan exhaustion or an unresolved JS/EF reference, causing the
/// caller to disable image-only skipping rather than silently assume absent overlap.
/// Individual image declarations and attached-stream types are inspected as loaded.
pub(super) fn classify(doc: &Document) -> Option<BTreeMap<ObjectId, u8>> {
    let mut roles = BTreeMap::new();
    let mut stack: Vec<_> = doc.objects.values().map(|v| (v, 0)).collect();
    let mut remaining = 100_000usize;
    for (id, object) in &doc.objects {
        if let Object::Stream(s) = object {
            let mut role = 0;
            if s.dict
                .get(b"Subtype")
                .ok()
                .and_then(|v| doc.dereference(v).ok())
                .is_some_and(|(_, v)| v.as_name().ok() == Some(b"Image"))
            {
                role |= 1;
            }
            if s.dict
                .get(b"Type")
                .is_ok_and(|v| v.as_name().ok() == Some(b"EmbeddedFile"))
            {
                role |= 4;
            }
            roles.insert(*id, role);
        }
    }
    while let Some((object, depth)) = stack.pop() {
        if remaining == 0 || depth > 64 {
            return None;
        }
        remaining -= 1;
        let dict = match object {
            Object::Dictionary(d) => Some(d),
            Object::Stream(s) => Some(&s.dict),
            Object::Array(values) => {
                stack.extend(values.iter().map(|v| (v, depth + 1)));
                None
            }
            _ => None,
        };
        if let Some(dict) = dict {
            if let Ok(js) = dict.get(b"JS") {
                match doc.dereference(js) {
                    Ok((Some(id), Object::Stream(_))) => *roles.entry(id).or_default() |= 2,
                    Err(_) => return None,
                    _ => {}
                }
            }
            if let Ok(ef) = dict.get(b"EF") {
                match doc.dereference(ef) {
                    Ok((_, Object::Dictionary(files))) => {
                        for (_, v) in files {
                            match doc.dereference(v) {
                                Ok((Some(id), Object::Stream(_))) => {
                                    *roles.entry(id).or_default() |= 4
                                }
                                Err(_) => return None,
                                _ => {}
                            }
                        }
                    }
                    Err(_) => return None,
                    _ => {}
                }
            }
            stack.extend(dict.iter().map(|(_, v)| (v, depth + 1)));
        }
    }
    Some(roles)
}
#[cfg(test)]
mod tests {
    use super::*;
    use sibilla_b_schema::{FormatExtractor, Limits};
    /// Verify an actual one-pixel RGB image stays classified without claiming pixel validation.
    #[test]
    fn raw_rgb_image_is_intentionally_not_decoded() {
        let mut doc = Document::new();
        let image = doc.add_object(lopdf::Stream::new(lopdf::dictionary! {"Type" => "XObject", "Subtype" => "Image", "Width" => 1, "Height" => 1, "ColorSpace" => "DeviceRGB", "BitsPerComponent" => 8}, vec![255,0,0]));
        let root = doc.add_object(lopdf::dictionary! {"Type" => "Catalog", "Image" => image});
        doc.trailer.set("Root", root);
        let mut bytes = Vec::new();
        doc.save_to(&mut bytes).unwrap();
        let result = crate::PdfExtractor.extract(&bytes, Limits::default());
        let f = result.format_features.unwrap();
        assert_eq!(
            f.stream_decode_status.as_deref(),
            Some("images_not_attempted")
        );
        assert_eq!(f.image_stream_decode_skipped_count, Some(1));
        assert_eq!(
            f.stream_decode_coverage_ratio,
            Some(f.stream_decode_success_count.unwrap() as f64 / f.stream_count.unwrap() as f64)
        );
        assert!(f.decoded_stream_size_mean.is_none());
    }
    /// Verify unresolved role references prevent image skipping instead of assuming image-only safety.
    #[test]
    fn unresolved_script_reference_disables_classification() {
        let mut doc = Document::new();
        doc.add_object(lopdf::dictionary! {"JS" => Object::Reference((9999,0))});
        assert!(classify(&doc).is_none());
    }
    /// Generate and serialize image, script, attachment, unknown and overlapping-role PDFs.
    #[test]
    fn custom_pdf_role_suite() {
        for (image, script, attachment) in [
            (true, false, false),
            (false, true, false),
            (false, false, true),
            (false, false, false),
            (true, true, false),
            (true, false, true),
        ] {
            let mut doc = Document::new();
            let mut dict = lopdf::dictionary! {};
            if image {
                dict.set("Subtype", "Image");
                dict.set("Filter", "DCTDecode");
                dict.set("Width", 1);
                dict.set("Height", 1);
            }
            let stream = doc.add_object(lopdf::Stream::new(dict, b"synthetic-test-bytes".to_vec()));
            let mut catalog = lopdf::dictionary! {"Type" => "Catalog", "TestStream" => stream};
            if script {
                let a = doc.add_object(lopdf::dictionary! {"S" => "JavaScript", "JS" => stream});
                catalog.set("OpenAction", a);
            }
            if attachment {
                let f = doc.add_object(lopdf::dictionary! {"Type" => "Filespec", "EF" => lopdf::dictionary! {"F" => stream}});
                catalog.set("Attachment", f);
            }
            let root = doc.add_object(catalog);
            doc.trailer.set("Root", root);
            let mut bytes = Vec::new();
            doc.save_to(&mut bytes).unwrap();
            let result = crate::PdfExtractor.extract(&bytes, Limits::default());
            let f = result.format_features.unwrap();
            assert_eq!(f.declared_image_stream_count, Some(usize::from(image)));
            assert_eq!(f.javascript_stream_count, Some(usize::from(script)));
            assert_eq!(f.attachment_stream_count, Some(usize::from(attachment)));
            assert_eq!(
                f.overlapping_stream_role_count,
                Some(usize::from(image && (script || attachment)))
            );
            assert_eq!(
                f.image_stream_decode_skipped_count,
                Some(usize::from(image && !script && !attachment))
            );
            if image && !script && !attachment {
                assert!(
                    !result
                        .error_code
                        .unwrap_or_default()
                        .contains("unsupported_stream_filter")
                );
                assert!(f.decoded_stream_size_mean.is_none());
            }
            if image && (script || attachment) {
                assert_eq!(f.malware.unwrap().payload_status, "partial");
            }
        }
    }
}
