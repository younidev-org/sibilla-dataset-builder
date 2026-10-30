# Read the feature table

[< Back to Sibilla Dataset Builder](../README.md) • [Documentation Hub](README.md)

Use the columns as measurements, not a malware verdict. `pdf-v3` is still in development.

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
| Unsupported filter or decode budget exceeded in decoded mode | Full decoded statistics null; subset statistics and coverage remain available; extraction marked partial |
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

- Full stream statistics cover every loaded stream, including XRef streams. `supported_decoded_stream_size_*` covers only successfully decoded streams.
- Missing or empty filter chains mean identity decoding.
- General stream decoding shares one aggregate measurement budget; targeted payload analysis has a separate budget of the same size.
- Parser-internal decompression is limited per stream; worker memory adds another ceiling.
- Typed-object counts cover loaded objects with explicit `/Type`, not every historical revision.
- Raw encoded-name candidates count `#XX` escapes in byte tokens and may include text.

| Unsupported measurement | Current behavior |
| --- | --- |
| Total historical XRef-table count | Null; the parser merges tables |
| Duplicate object IDs or inaccessible-object counts | Null; discarded objects cannot be recovered from the loaded map |
| Legacy document-level JavaScript total | Null; use the new context-specific action counts |
| Embedded payload summaries | Targeted decoded total/max sizes available; no recursive archive analysis |
| Historical revisions and arbitrary structural-path vocabulary | Not implemented; action relationships cover the loaded document |

For exact fields, see [`sibilla-b-schema`](../crates/sibilla-b-schema/src/lib.rs) and the [table schema](../crates/sibilla-b-output/src/lib.rs).

### Stream coverage (`pdf-v3`)

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

## Static malware-related measurements (`pdf-v3`)

The prefix for these columns is `extraction_format_features_malware_`.

| Columns | Meaning |
| --- | --- |
| `structure_status`, `payload_status` | Structural analysis: complete/partial; payload analysis: complete/partial/not_attempted |
| `reachable_objects`, `unreachable_objects` | Loaded indirect objects reachable/unreachable from the trailer; unreachable does not mean malicious |
| `broken_references`, `max_graph_depth` | Missing referenced identities and maximum observed graph traversal depth (not a shortest-path distance) |
| `action_count`, `javascript_action_count` | Action relationships discovered from trigger entries and Next chains |
| `document_open_javascript_count` | JavaScript reached through catalog OpenAction chains |
| `additional_javascript_count` | JavaScript from document/page additional actions |
| `annotation_javascript_count`, `form_javascript_count` | JavaScript from annotation and form action entries |
| `uri_action_count`, `launch_action_count`, `navigation_action_count` | Typed URI, Launch, and GoTo/GoToR/GoToE/Named action relationships |
| `action_linked_attachments` | Action F entries resolving to file specifications with EF dictionaries |
| `javascript_count`, `javascript_bytes` | Reachable JavaScript action dictionaries carrying JS values, and decoded payload bytes |
| `javascript_suspicious_api_tokens` | Case-sensitive substring occurrences of eval, unescape, fromCharCode, exportDataObject, launchURL, submitForm, util.printf, Collab, getAnnots |
| `javascript_escape_sequences`, `javascript_long_strings` | Backslash-x/backslash-u/percent-u sequences and closed quoted runs of at least 256 bytes |
| `attachment_count` | Embedded-file entries reached via EF; aliases to the same indirect stream within one EF dictionary count once |
| `attachment_decoded_bytes`, `attachment_max_decoded_bytes` | Total and largest decoded attachment payload |
| `attachment_*_signatures` | Leading-byte matches for PE (MZ), ELF, PDF, ZIP, and shebang scripts; executable count also includes common Mach-O magic values |
| `url_count`, `url_ip_literal_count` | Reachable URI string entries and those parsed with literal IPv4/IPv6 hosts |
| `url_unusual_scheme_count`, `url_max_length` | URI entries outside http/https/mailto (including unparseable values), and maximum stored byte length |
| `payload_attempted_count`, `payload_decoded_count`, `payload_failed_count` | Targeted script/attachment payload attempts and results |

Traversal is capped at 64 levels and 100,000 visits. Action references are deduplicated per trigger context so cycles terminate; a shared action may count in multiple contexts. Direct dictionaries are inspected as encountered. Counts are observations within the loaded document, not reconstruction of historical revisions or every reader's interpretation. Missing references are counted; an exhausted traversal nulls all measurements rather than publishing incomplete totals.

Structural mode leaves payload byte/signature/lexical measurements and payload attempt counts null. In decoded mode, any failed targeted payload nulls payload-derived aggregate measurements; attempt counts and status remain available. Payload strings with UTF-16 BOMs are normalized for lexical script scanning; reported byte sizes refer to decoded PDF payload bytes before normalization. Lexical counts are not a JavaScript parser, deobfuscator, or behavior verdict. File magic matches do not validate an executable or recursively inspect archives.

Targeted payload decoding and general stream measurement each use their own aggregate `--max-decompressed-mb` budget. Parser-internal decoding and worker memory restrictions still apply. Targeted payloads are inspected first; structural mode does not attempt those payloads. Coverage status strings stay in the manifest, outside the feature table. Use the same mode for all dataset inputs.

`catalog_action_reference_count` now counts the presence of catalog OpenAction and AA entry points (0–2). `document_javascript_action_count` remains unavailable; use the explicit context-specific counts above. The other previously unavailable historical measurements remain null. Old `pdf-v1` and `pdf-v2` tables/checkpoints require re-extraction for this schema.
