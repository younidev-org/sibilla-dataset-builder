//! Independent image metadata and optional bounded JPEG analysis.
//!
//! Metadata covers loaded streams declaring `Subtype Image`, including streams with
//! overlapping script/attachment roles. JPEG pixel decoding is independent of general
//! stream statistics: an image may be skipped there and successfully decoded here.
//!
//! Successful-subset dimensions and byte totals must be interpreted alongside decoded
//! and failed counts. Decoder rejection can mean unsupported JPEG details, resource
//! exhaustion, or malformed data; it does not establish malware or image safety.
use lopdf::{Document, Object};
use sibilla_b_schema::{ImageFeatures, Limits};
/// Resolve a positive integer image parameter without trusting declared allocation sizes.
fn integer(doc: &Document, dict: &lopdf::Dictionary, key: &[u8]) -> Option<u64> {
    dict.get(key)
        .ok()
        .and_then(|v| doc.dereference(v).ok())
        .and_then(|(_, v)| v.as_i64().ok())
        .and_then(|v| u64::try_from(v).ok())
        .filter(|v| *v > 0)
}
/// Inspect declared image parameters and optionally decode supported JPEG streams.
///
/// `decode_images` selects pixel work; otherwise pixel counters remain null. Metadata
/// maxima describe positive values actually present, using zero if none were available.
/// Supported filter prefixes are decoded before a terminal `DCTDecode` filter.
///
/// The image stage has its own aggregate allowance from `max_decompressed_bytes`.
/// JPEG header dimensions and pixel format are checked before pixel decoding, and
/// the decoder output-buffer cap is also set. This does not account for every parser
/// or decoder working allocation; the caller must retain worker OS memory/time limits.
/// No output pixels are persisted and PDF color rendering semantics are not validated.
pub(super) fn analyze(doc: &Document, limits: Limits) -> ImageFeatures {
    let mut f = ImageFeatures::default();
    let mut color_counts = [0; 4];
    let mut max_bits = 0;
    let mut masks = 0;
    let mut count = 0;
    let mut invalid = 0;
    let mut encoded = 0;
    let mut width = 0;
    let mut height = 0;
    let mut decoded = 0;
    let mut decoded_bytes = 0;
    let mut decoded_width = 0;
    let mut decoded_height = 0;
    let mut mismatches = 0;
    let mut unsupported = 0;
    let mut invalid_data = 0;
    let mut budget = 0;
    let mut remaining = limits.max_decompressed_bytes.min(usize::MAX as u64) as usize;
    for object in doc.objects.values() {
        let Object::Stream(stream) = object else {
            continue;
        };
        if !stream
            .dict
            .get(b"Subtype")
            .ok()
            .and_then(|v| doc.dereference(v).ok())
            .is_some_and(|(_, v)| v.as_name().ok() == Some(b"Image"))
        {
            continue;
        }
        count += 1;
        encoded += stream.content.len() as u64;
        let w = integer(doc, &stream.dict, b"Width");
        let h = integer(doc, &stream.dict, b"Height");
        width = width.max(w.unwrap_or(0));
        height = height.max(h.unwrap_or(0));
        let mask = stream
            .dict
            .get(b"ImageMask")
            .is_ok_and(|v| v.as_bool().unwrap_or(false));
        let bits = integer(doc, &stream.dict, b"BitsPerComponent");
        masks += u64::from(mask);
        max_bits = max_bits.max(bits.unwrap_or(0));
        let color = stream
            .dict
            .get(b"ColorSpace")
            .ok()
            .and_then(|v| doc.dereference(v).ok())
            .map(|(_, v)| v);
        let color = match color {
            Some(Object::Name(n)) => Some(n.as_slice()),
            Some(Object::Array(a)) => a.first().and_then(|v| v.as_name().ok()),
            _ => None,
        };
        color_counts[match color {
            Some(b"DeviceGray" | b"CalGray") => 0,
            Some(b"DeviceRGB" | b"CalRGB") => 1,
            Some(b"DeviceCMYK") => 2,
            _ => 3,
        }] += 1;
        let jpx = super::resolved_stream(doc, stream).ok().is_some_and(|s| {
            s.filters()
                .is_ok_and(|f| f.contains(&b"JPXDecode".as_slice()))
        });
        if w.is_none()
            || h.is_none()
            || (!mask && !(jpx && bits.is_none()) && !matches!(bits, Some(1 | 2 | 4 | 8 | 16)))
        {
            invalid += 1;
        }
        if !limits.decode_images {
            continue;
        }
        let Ok(mut stream) = super::resolved_stream(doc, stream).map(|s| s.into_owned()) else {
            invalid_data += 1;
            continue;
        };
        let Ok(filters) = stream.filters() else {
            unsupported += 1;
            continue;
        };
        if filters.last().copied() != Some(b"DCTDecode".as_slice()) {
            unsupported += 1;
            continue;
        }
        let prefix: Vec<_> = filters[..filters.len() - 1]
            .iter()
            .map(|s| Object::Name(s.to_vec()))
            .collect();
        let bytes = if prefix.is_empty() {
            stream.content
        } else {
            stream.dict.set("Filter", Object::Array(prefix));
            match stream.decompressed_content_with_limit(remaining) {
                Ok(bytes) => bytes,
                Err(lopdf::Error::Decompress(lopdf::DecompressError::MemoryLimitExceeded {
                    ..
                })) => {
                    budget += 1;
                    continue;
                }
                Err(lopdf::Error::Unimplemented(_)) => {
                    unsupported += 1;
                    continue;
                }
                Err(_) => {
                    invalid_data += 1;
                    continue;
                }
            }
        };
        let mut decoder = jpeg_decoder::Decoder::new(bytes.as_slice());
        decoder.set_max_decoding_buffer_size(remaining);
        if decoder.read_info().is_err() {
            invalid_data += 1;
            continue;
        }
        let Some(info) = decoder.info() else {
            invalid_data += 1;
            continue;
        };
        let needed = usize::from(info.width)
            .checked_mul(usize::from(info.height))
            .and_then(|n| n.checked_mul(info.pixel_format.pixel_bytes()));
        if needed.is_none_or(|n| n > remaining) {
            budget += 1;
            continue;
        }
        match decoder.decode() {
            Ok(pixels) if pixels.len() <= remaining => {
                remaining -= pixels.len();
                decoded += 1;
                decoded_bytes += pixels.len() as u64;
                decoded_width = decoded_width.max(u64::from(info.width));
                decoded_height = decoded_height.max(u64::from(info.height));
                if w != Some(u64::from(info.width)) || h != Some(u64::from(info.height)) {
                    mismatches += 1;
                }
            }
            _ => invalid_data += 1,
        }
    }
    f.decode_status = if !limits.decode_images {
        "not_attempted"
    } else if unsupported + invalid_data + budget > 0 {
        "partial"
    } else {
        "complete"
    }
    .into();
    f.grayscale_count = Some(color_counts[0]);
    f.rgb_count = Some(color_counts[1]);
    f.cmyk_count = Some(color_counts[2]);
    f.other_color_space_count = Some(color_counts[3]);
    f.max_bits_per_component = Some(max_bits);
    f.image_mask_count = Some(masks);
    f.image_count = (true).then_some(count);
    f.invalid_parameters_count = (true).then_some(invalid);
    f.encoded_bytes = (true).then_some(encoded);
    f.max_declared_width = (true).then_some(width);
    f.max_declared_height = (true).then_some(height);
    f.decoded_count = (limits.decode_images).then_some(decoded);
    f.decoded_bytes = (limits.decode_images).then_some(decoded_bytes);
    f.max_decoded_width = (limits.decode_images).then_some(decoded_width);
    f.max_decoded_height = (limits.decode_images).then_some(decoded_height);
    f.dimension_mismatch_count = (limits.decode_images).then_some(mismatches);
    f.unsupported_count = (limits.decode_images).then_some(unsupported);
    f.invalid_data_count = (limits.decode_images).then_some(invalid_data);
    f.budget_exceeded_count = (limits.decode_images).then_some(budget);
    f
}
#[cfg(test)]
mod tests {
    use super::*;
    /// Build a custom PDF stream from a real JPEG, with independently declared dimensions.
    fn jpeg_doc(width: i64, bytes: Vec<u8>) -> Document {
        let mut doc = Document::new();
        doc.add_object(lopdf::Stream::new(lopdf::dictionary! {"Subtype"=>"Image","Filter"=>"DCTDecode","Width"=>width,"Height"=>3,"BitsPerComponent"=>8,"ColorSpace"=>"DeviceRGB"},bytes));
        doc
    }
    /// Verify a valid JPEG wrapped in ASCIIHex is unwrapped before pixel decoding.
    #[test]
    fn jpeg_filter_prefix_is_decoded() {
        let bytes = include_bytes!("../tests/fixtures/red-2x3.jpg");
        let encoded = bytes.iter().map(|b| format!("{b:02x}")).collect::<String>() + ">";
        let mut doc = jpeg_doc(2, encoded.into_bytes());
        for object in doc.objects.values_mut() {
            if let Object::Stream(s) = object {
                s.dict.set(
                    "Filter",
                    Object::Array(vec![
                        Object::Name(b"ASCIIHexDecode".to_vec()),
                        Object::Name(b"DCTDecode".to_vec()),
                    ]),
                );
            }
        }
        let f = analyze(
            &doc,
            Limits {
                decode_images: true,
                ..Limits::default()
            },
        );
        assert_eq!(f.decoded_count, Some(1));
        assert_eq!(f.invalid_data_count, Some(0));
    }
    /// Verify actual pixels, dimension mismatches, invalid data and exhausted budgets remain distinct.
    #[test]
    fn jpeg_outcomes_are_distinct() {
        let bytes = include_bytes!("../tests/fixtures/red-2x3.jpg").to_vec();
        let limits = Limits {
            decode_images: true,
            ..Limits::default()
        };
        let f = analyze(&jpeg_doc(2, bytes.clone()), limits);
        assert_eq!(f.decoded_count, Some(1));
        assert_eq!(f.decoded_bytes, Some(18));
        assert_eq!(f.dimension_mismatch_count, Some(0));
        assert_eq!(
            analyze(&jpeg_doc(9, bytes.clone()), limits).dimension_mismatch_count,
            Some(1)
        );
        assert_eq!(
            analyze(&jpeg_doc(2, vec![0, 1, 2]), limits).invalid_data_count,
            Some(1)
        );
        assert_eq!(
            analyze(
                &jpeg_doc(2, bytes.clone()),
                Limits {
                    max_decompressed_bytes: 1,
                    ..limits
                }
            )
            .budget_exceeded_count,
            Some(1)
        );
        assert_eq!(
            analyze(&jpeg_doc(2, bytes), Limits::default()).decoded_count,
            None
        );
    }
}
