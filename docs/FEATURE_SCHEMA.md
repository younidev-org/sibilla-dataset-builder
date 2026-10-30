# Read the feature table

[< Back to Sibilla Dataset Builder](../README.md) • [Documentation Hub](README.md)

Use the columns as measurements, not a malware verdict. `pdf-v2` is still in development.

## Start with quality

| Column | What to check |
| --- | --- |
| `extraction_status` | Whether the record is complete, partial, rejected, timed out, or failed |
| `extraction_parse_status` | Whether parsed measurements are available |
| `extraction_failure_stage` | Where a problem occurred |
| `extraction_error_code` | The fixed failure reason |
| `sample_id` | SHA-256 join key; remove before training |
| `label` | User-supplied `0`, `1`, or null |

Unavailable measurements stay null. Do not replace them with zero without an explicit modeling decision.

| Situation | Expected values |
| --- | --- |
| Malformed PDF | Byte features and raw counts preserved; unavailable semantic fields null |
| Oversized file | No invented byte statistics |
| Password required | `encrypted=true`; byte/raw features preserved; semantic fields null |
| Empty-password encryption | Still flagged as encrypted after decryption |
| Unsupported filter or decode budget exceeded | Decoded statistics null; extraction marked partial |
| Worker killed | Statistics may be unavailable and remain null |

Error codes may contain multiple fixed reasons separated by a pipe. `sibilla-b inspect FILE` counts each reason separately; exported column names remain unchanged.

## Choose feature groups

| Group | Includes |
| --- | --- |
| Byte statistics | Size, normalized 256-bin histogram, byte ratios, global and block entropy |
| PDF structure | Header/version, EOF markers, loaded objects/streams/references, catalog flags |
| Active-content indicators | Separate raw-token and parsed-name counts |
| Embedded files | Counts of loaded objects with explicit embedded-file or Filespec types |
| External references | URI strings and distinct canonical hosts, without network access |
| Streams | Raw/decoded sizes, filter counts/depths, and high-entropy stream ratio |

Raw counts can include strings, comments, and stream bytes. Parsed names describe loaded objects. Neither proves action reachability or malicious behavior.

## Read numeric values correctly

| Measurement | Definition |
| --- | --- |
| Global entropy | Shannon entropy in bits per byte |
| Block entropy | 4096-byte chunks, including the final short chunk |
| Block standard deviation | Population standard deviation |
| High entropy | Strictly greater than 7.5 bits/byte |
| Histogram | 256 normalized frequencies, in byte order |
| ASCII ratio | Bytes 0–127 |
| Printable ratio | Bytes 32–126 |
| Empty input statistics | Zero for byte statistics |
| PDF header | Must begin within the first 1024 bytes |
| Page count | Derived from the parsed page tree |

Histogram columns run from `extraction_common_features_byte_histogram_000` through `_255`.

## Work with CSV or Parquet

| Value | Representation |
| --- | --- |
| Missing value in CSV | `\N` |
| String beginning with a backslash | Leading backslash escaped |
| Counts | Nullable Int64 |
| Measurements | Nullable Float64 |
| Presence flags | Nullable Boolean |

CSV and Parquet preserve the same typed values, including empty strings. Readers reject incompatible schemas and nonfinite numbers.

## Know which measurements are limited

- Stream statistics include every loaded stream, including XRef streams.
- Missing or empty filter chains mean identity decoding.
- Explicit decoding shares one aggregate measurement budget across streams.
- Parser-internal decompression is limited per stream; worker memory adds another ceiling.
- Typed-object counts cover loaded objects with explicit `/Type`, not every historical revision.
- Raw encoded-name candidates count `#XX` escapes in byte tokens and may include text.

| Unsupported measurement | Current behavior |
| --- | --- |
| Total historical XRef-table count | Null; the parser merges tables |
| Duplicate object IDs or inaccessible-object counts | Null; discarded objects cannot be recovered from the loaded map |
| Document-level JavaScript and catalog action reachability | Null; graph traversal is not implemented |
| Embedded-only size summaries | Not implemented |
| Complete revision/action graphs | Not implemented |

For exact fields, see [`sibilla-b-schema`](../crates/sibilla-b-schema/src/lib.rs) and the [table schema](../crates/sibilla-b-output/src/lib.rs).

### Stream coverage (`pdf-v2`)

Fields below use the `extraction_format_features_` prefix.

| Fields | Meaning |
| --- | --- |
| `stream_mode` | `structural` or `decoded` |
| `stream_decode_status` | `not_attempted`, `unavailable`, `complete`, or `partial` |
| `stream_decode_success_count` | Streams successfully decoded |
| `stream_decode_unsupported_count` | Streams blocked by unsupported codecs |
| `stream_decode_unsupported_filters` | Sorted unsupported filter names separated by a pipe |
| `stream_decode_error_count` | Other stream failures, including decoding budget exhaustion |
| `stream_decode_coverage_ratio` | Decoded streams / total streams; 1 for an empty stream set |
| `supported_decoded_stream_size_*` | Size statistics over successfully decoded streams only |

Counts, coverage and subset statistics are null when decoding is not attempted or unavailable. Subset statistics are null if no stream decoded. Existing `decoded_stream_size_*` and `high_entropy_stream_ratio` still require complete coverage. In structural mode they remain null.

The existing `extraction_parse_status` reports whether PDF structure was parsed independently of decoding status. Mode, decoding status and unsupported filter names stay in the manifest and are excluded from the numeric feature table. Indirect filter and parameter references are resolved with bounded reference traversal.
