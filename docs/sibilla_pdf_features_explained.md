# Sibilla PDF Dataset — Feature Explanations

[< Back to Sibilla Dataset Builder](../README.md) • [Documentation Hub](README.md)

This document explains the static PDF features visible in the Parquet dataset screenshots, including their meaning, possible security relevance, and limitations when training a malware risk classifier.

> **Current definitions:** This guide explains the original feature families. For exact `pdf-v4` column definitions, null handling, and the new action, JavaScript, attachment, graph, and URL features, use the [schema guide](FEATURE_SCHEMA.md). Fields such as `document_javascript_action_count`, `inaccessible_objects`, `duplicate_object_ids`, and `xref_table_count` remain unavailable; their intended meanings below do not imply that the extractor measures them.

## Feature families at a glance

| Category | What it measures |
| --- | --- |
| Common features | Byte distribution, entropy, file size, basic file characteristics |
| PDF structure | Pages, objects, streams, references, metadata |
| Actions and scripting | JavaScript, automatic actions, links and external interactions |
| Encoding and compression | Filters, compressed streams and decoding complexity |
| Structural anomalies | Malformed or unusual object references, header and EOF properties |
| Sample identification | An identifier for tracing the source sample |

These are **static features**: they characterize a PDF without opening it in a PDF reader or executing its scripting capabilities. No single feature proves that a PDF is malicious.

---

## 1. Common features: raw file characteristics

All fields in this section begin with:

`extraction_common_features_`

### 1.1 Byte histogram: 256 features

A histogram field exists for every possible byte value, from:

- `extraction_common_features_byte_histogram_000`
- ...
- `extraction_common_features_byte_histogram_255`

A byte is an unsigned 8-bit value in the range **0–255**. Each histogram feature records the normalized frequency (0–1) of one byte value across the file. Nonempty-file histogram values sum to approximately 1.

The screenshot specifically shows:

| Field suffix | Hex byte | Meaning |
| --- | --- | --- |
| `byte_histogram_248` | `F8` | Occurrences/frequency of byte 248 |
| `byte_histogram_249` | `F9` | Occurrences/frequency of byte 249 |
| `byte_histogram_250` | `FA` | Occurrences/frequency of byte 250 |
| `byte_histogram_251` | `FB` | Occurrences/frequency of byte 251 |
| `byte_histogram_252` | `FC` | Occurrences/frequency of byte 252 |
| `byte_histogram_253` | `FD` | Occurrences/frequency of byte 253 |
| `byte_histogram_254` | `FE` | Occurrences/frequency of byte 254 |
| `byte_histogram_255` | `FF` | Occurrences/frequency of byte 255 |

The remaining 248 histogram fields work identically.

**Example** — for the eight bytes:

```text
41 42 41 00 FF 41 42 00
```

The nonzero histogram counts are:

| Byte | Count | Fraction |
| --- | ---: | ---: |
| `0x00` | 2 | 0.250 |
| `0x41` | 3 | 0.375 |
| `0x42` | 2 | 0.250 |
| `0xFF` | 1 | 0.125 |

All other byte values occur zero times.

**Security relevance:** Byte distributions may distinguish textual, compressed, encrypted, or embedded binary content. They are broad statistical characteristics, not direct malicious-behavior signals. Legitimate compressed PDFs can look statistically similar to suspicious PDFs.

### 1.2 Entropy and other common statistics

Shannon byte entropy is:

\[
H = -\sum_{i=0}^{255} p_i\log_2(p_i)
\]

where `p_i` is the probability of byte `i`, and zero-probability terms contribute zero. Conventional byte entropy ranges from **0 to 8 bits per byte**.

| Full field | Meaning |
| --- | --- |
| `extraction_common_features_entropy_global` | Entropy across the complete file |
| `extraction_common_features_entropy_block_max` | Highest entropy among the file's analyzed blocks |
| `extraction_common_features_entropy_block_mean` | Mean entropy across analyzed blocks |
| `extraction_common_features_entropy_block_min` | Lowest block entropy |
| `extraction_common_features_entropy_block_std` | Standard deviation of block entropy |
| `extraction_common_features_high_entropy_block_ratio` | Fraction of analyzed blocks above the extractor's high-entropy threshold |
| `extraction_common_features_printable_ratio` | Fraction of bytes considered printable by the extractor |
| `extraction_common_features_zero_byte_ratio` | Fraction of bytes equal to `0x00` |
| `extraction_common_features_size_bytes` | Original file size in bytes |
| `extraction_common_features_magic_present` | Whether the extractor detected the expected PDF signature, typically `%PDF-` |

Illustrative entropy interpretation (not calibrated detection thresholds):

| Entropy | Typical interpretation |
| --- | --- |
| 0–3 | Highly repetitive or simple byte patterns |
| 3–6 | More varied byte content |
| 6–8 | Potentially compressed, encrypted, or otherwise highly varied data |

**Why block entropy matters:** A PDF can have moderate overall entropy while containing one very high-entropy region. `entropy_block_max` can capture that region; `high_entropy_block_ratio` indicates how widespread such regions are.

**Important limitations:** A high-entropy region can be an ordinary compressed image or font. Sibilla uses 4096-byte blocks, includes the final short block, and defines high entropy as strictly above 7.5 bits per byte.

---

## 2. PDF format features: document structure

All the following fields begin with:

`extraction_format_features_`

### 2.1 Document structure and metadata

| Field suffix | Explanation |
| --- | --- |
| `catalog_present` | Whether the document catalog (PDF root object) was detected |
| `acroform_present` | Whether an interactive AcroForm structure is present |
| `metadata_present` | Whether PDF metadata was detected |
| `encrypted` | Whether PDF document encryption is indicated |
| `linearized` | Whether the PDF uses a linearized structure for progressive network loading |
| `page_count` | Number of pages counted by the parser |
| `object_count` | Number of PDF objects counted according to the parser's rules |
| `object_stream_count` | Number of `/ObjStm` object streams that package PDF objects |
| `stream_count` | Number of PDF data streams found |
| `reference_count` | Number of indirect object references counted |
| `filespec_count` | Number of file specification structures found |
| `embedded_file_count` | Number of embedded files discovered |
| `version` | PDF specification version, such as 1.4, 1.7, or 2.0; verify numeric encoding |

A simplified document structure looks like:

```text
PDF Catalog (root)
├── Pages
│   └── Page objects → content streams, images, fonts
├── Actions
│   └── Possible JavaScript or other action objects
├── AcroForm
│   └── Interactive form fields
└── Metadata
```

A high `object_count`, many streams, or an AcroForm is **not automatically suspicious**. Large or interactive legitimate PDFs often have complex object graphs.

### 2.2 Actions and external resources

| Field suffix | Explanation |
| --- | --- |
| `catalog_action_reference_count` | Number of action references associated with the catalog, according to extractor traversal rules |
| `document_javascript_action_count` | Number of JavaScript actions identified at document level |
| `external_uri_count` | Number of externally referring URIs found, subject to counting semantics |
| `external_host_count` | Number of network hosts referenced; whether duplicate hosts count once or multiple times depends on the implementation |

These features are especially relevant when examining documents that may contain behavior triggered on opening, clicking, or interacting with a PDF. For instance, `/OpenAction` can identify an action associated with opening the document, and JavaScript action objects can identify scripts. **Detection of these constructs does not imply the target PDF viewer will execute them.**

### 2.3 Structural anomalies and parser observations

| Field suffix | Explanation |
| --- | --- |
| `duplicate_object_ids` | Count of repeated object identifiers under the extractor's duplicate-detection policy |
| `inaccessible_objects` | Count of objects that could not be accessed, resolved, or decoded |
| `encoded_name_raw_count` | Count of PDF names containing hexadecimal name escapes such as `#61`, under raw scanning rules |
| `header_offset` | Position in bytes where the PDF header was found relative to file start |
| `eof_count` | Number of `%%EOF` markers detected |
| `incremental_update_raw_count` | Number of apparent incremental-update indicators found via raw scanning |
| `trailing_eof` | Extractor-defined measurement concerning the terminal EOF marker or bytes following it; inspect code to establish exact meaning/type |
| `xref_stream_count` | Number of cross-reference streams found |
| `xref_table_count` | Number of traditional cross-reference tables found |

**Why these can matter:**

- **`header_offset`:** A conventional PDF often begins with a `%PDF-` header. Nonzero offsets can occur in unusual or nonstandard files, including polyglot constructions, but are not inherently malicious.
- **`encoded_name_raw_count`:** PDF names may legitimately encode characters. For example `/J#61vaScript` decodes to `/JavaScript`, since hexadecimal `61` represents `a`. This can also make exact-byte matching less effective.
- **`eof_count` and `incremental_update_raw_count`:** PDF incremental updates append data and may legitimately produce multiple `%%EOF` markers. Counting markers does not reliably count malicious revisions.
- **`duplicate_object_ids`:** Repeated identifiers may be part of legitimate revisions or indicate conflicts; whether they are anomalies depends on revision-aware parsing.
- **`inaccessible_objects`:** Parsing failures might reveal malformed documents or simply unsupported or damaged structures. They should be distinguishable from absent objects.

---

## 3. PDF streams, compression, and filters

### 3.1 Raw and decoded stream sizes

A PDF stream can contain compressed page content, images, fonts, attachments, or other binary data. The **raw size** concerns the encoded stream bytes in the PDF; the **decoded size** concerns output after supported filters have been applied.

| Field suffix | Explanation |
| --- | --- |
| `raw_stream_size_max` | Largest stored/encoded stream size |
| `raw_stream_size_mean` | Average stored/encoded stream size |
| `raw_stream_size_min` | Smallest stored/encoded stream size |
| `raw_stream_size_std` | Standard deviation of stored/encoded stream sizes |
| `decoded_stream_size_max` | Largest decoded stream size, available only with complete coverage |
| `decoded_stream_size_mean` | Average decoded stream size, available only with complete coverage |
| `decoded_stream_size_min` | Smallest decoded stream size, available only with complete coverage |
| `decoded_stream_size_std` | Standard deviation of decoded stream sizes, available only with complete coverage |
| `high_entropy_stream_ratio` | Fraction of streams classified as high entropy under extractor rules |

**Example:** A compressed stream might occupy 25 KB in the file and expand to 100 KB after decoding. That is normal for many compression methods. The security meaning depends on the size distribution, decoding behavior, and how it compares with benign documents.

If any stream cannot be decoded, the full `decoded_stream_size_*` statistics remain null. `supported_decoded_stream_size_*` describes the successfully decoded subset; check `stream_decode_coverage_ratio`. Structural mode leaves decoded measurements null.

### 3.2 Filter counts

Every field here has the prefix:

`extraction_format_features_filter_counts_`

| Filter suffix | Explanation |
| --- | --- |
| `ASCII85Decode` | Uses base-85 text encoding to represent binary bytes |
| `ASCIIHexDecode` | Uses hexadecimal text encoding to represent binary bytes |
| `CCITTFaxDecode` | Fax-style encoding for typically monochrome image data |
| `Crypt` | Cryptographic stream decoding filter |
| `DCTDecode` | JPEG-style image encoding |
| `FlateDecode` | DEFLATE/zlib compression |
| `JBIG2Decode` | JBIG2 image compression for bi-level images |
| `JPXDecode` | JPEG 2000 image encoding |
| `LZWDecode` | Lempel–Ziv–Welch compression |
| `RunLengthDecode` | Run-length compression |
| `other` | Other filters outside the named categories |

The column values generally represent how often each filter is seen; verify whether the implementation counts occurrences within filter chains, references, or unique streams.

**Interpretation notes:**

- `FlateDecode` is common in ordinary PDFs.
- `JBIG2Decode` identifies a codec and possible decoder attack surface; it is not evidence of exploitation.
- `Crypt` as a stream filter is not equivalent to the document-level `encrypted` flag.

### 3.3 Filter depth and suspicious chains

| Field suffix | Explanation |
| --- | --- |
| `filter_depth_max` | Largest number of filters used on a stream |
| `filter_depth_mean` | Average filter chain length |
| `filter_depth_min` | Smallest filter chain length |
| `filter_depth_std` | Standard deviation of filter chain lengths |
| `suspicious_filter_chain_count` | Number of filter chains matching extractor-defined suspicious-pattern rules |

A stream may be decoded through multiple filters:

```text
Stored stream
    |
    v
ASCII85Decode
    |
    v
FlateDecode
    |
    v
Decoded content
```

This example has a filter depth of **2**.

Unusual combinations, unsupported filters, and very long chains may merit attention, but **`suspicious_filter_chain_count` is an extractor heuristic**, not a standardized PDF property. Its exact rules need to be documented and tested.

---

## 4. Parsed names and raw tokens: 32 features

Two groups share the same 16 suffixes:

- `extraction_format_features_parsed_names_<name>`
- `extraction_format_features_raw_tokens_<name>`

For each suffix listed below, **both** fields exist in the screenshots, making 32 fields total.

### 4.1 Difference between parsed names and raw tokens

Suppose a PDF contains:

```text
10 0 obj
<<
    /S /JavaScript
    /JS (app.alert("Hello"))
>>
endobj
```

A parser can identify actual PDF name objects such as `/JavaScript` and `/JS`. A raw scanner instead counts text or byte patterns, potentially including text within strings, comments, or damaged structures.

| Property | Parsed names | Raw tokens |
| --- | --- | --- |
| PDF structure awareness | Yes | Limited |
| Can detect name objects | Yes | May match same byte sequences |
| May count non-semantic text occurrences | Less often | More often |
| May find suspicious text in malformed data | Depends on parser recovery | Often, depending on scanner |
| Handles `#XX` encoded PDF names | Typically when decoded by parser | Depends on raw scanner |
| Proves that a viewer executes behavior | No | No |

For example, `/J#61vaScript` is a valid encoded representation of the PDF name `/JavaScript`. A parser that decodes PDF names can identify the name, while a raw scanner looking only for literal `/JavaScript` might miss it.

### 4.2 All 16 name/token suffixes

| Suffix (exists as `parsed_names_*` and `raw_tokens_*`) | Meaning | Security relevance |
| --- | --- | --- |
| `AA` | Additional Actions associated with events | Actions may be triggered by document or form interactions |
| `AcroForm` | Interactive PDF forms | Common legitimate feature; can involve scripts |
| `EmbeddedFile` | Embedded file-related name | Potentially identifies attached content |
| `Filespec` | File specification object/name | May refer to embedded or external files |
| `GoToR` | Go To Remote action | Navigation to destinations in another document |
| `ImportData` | Import form data action | May involve retrieving data from a file |
| `JBIG2Decode` | JBIG2 decoding filter name | Additional image-decoder parsing surface |
| `JS` | Name used for a JavaScript script in PDF structures | Script-related indicator |
| `JavaScript` | JavaScript action subtype or associated name | Script-related indicator |
| `Launch` | Launch action | Requests application launch or file opening |
| `ObjStm` | Object stream | Encapsulates other objects that require parsing |
| `OpenAction` | Document-open action/destination | Relevant to possible automatic behavior |
| `RichMedia` | Rich multimedia content | Additional rendering/interactive functionality |
| `SubmitForm` | Submit form data action | Potential outgoing data transfer |
| `URI` | Uniform Resource Identifier action/name | External link or URI functionality |
| `XFA` | XML Forms Architecture | Complex forms and XML parsing surface |

**Example counts (illustrative only):**

| Feature | Example |
| --- | ---: |
| `parsed_names_JavaScript` | 1 |
| `raw_tokens_JavaScript` | 3 |
| `parsed_names_OpenAction` | 1 |
| `raw_tokens_OpenAction` | 1 |
| `encoded_name_raw_count` | 4 |

Different parsed and raw counts can signal different scanning coverage, name encoding, textual mentions not attached to actual objects, or recovery behavior. They are **not proof** of evasion by themselves.

### 4.3 Useful investigation groups

| Group | Related suffixes | What to investigate |
| --- | --- | --- |
| Scripts and actions | `JS`, `JavaScript`, `AA`, `OpenAction` | Declared scripts and event-triggered behavior |
| External interaction | `Launch`, `URI`, `GoToR`, `SubmitForm`, `ImportData` | File access, navigation, and submission functionality |
| Embedded/complex content | `EmbeddedFile`, `Filespec`, `RichMedia`, `XFA`, `JBIG2Decode`, `ObjStm`, `AcroForm` | Extra content and parsing complexity |

A PDF may contain any of these features and still be benign.

---

## 5. Sample identification

| Field | Explanation |
| --- | --- |
| `sample_id` | Dataset sample identifier, such as a generated ID, content hash, or source key, depending on the dataset builder |

This column is for tracing predictions back to source records. **Do not train on `sample_id` as a predictive numeric/categorical feature.** It can create source-specific leakage without generalizable security signal.

---

## 6. Relevance to Sibilla's static malware model

The most useful features should be determined experimentally, not by ranking suspicious-sounding names alone.

| Feature group | Potential signal | Important limitation |
| --- | --- | --- |
| JavaScript and action counts | Scripts and automatic action declarations | Legitimate interactive PDFs use them |
| Structural anomalies | Malformed or unusual structures | Benign corruption and revision formats exist |
| Encoded name counts | Unusual name encodings | Name escaping is PDF-standard behavior |
| Embedded files | Attached content and nested material | Normal documents can contain attachments |
| Entropy | Compressed/encrypted regions | Compression and encryption often are legitimate |
| Raw-vs-parsed count differences | Parser visibility or structural inconsistencies | Scanner implementations may produce differences |
| Filter chains | Compression/decoding complexity | Multi-stage filters are legitimate |
| Byte histograms | Statistical characteristics of file bodies | Often weakly interpretable alone |

### 6.1 Recommended training and evaluation practices

1. **Keep the full feature set initially.** Train an initial tree-based baseline (e.g., LightGBM or XGBoost) and use ablation studies, permutation importance, and error analysis to identify what helps.
2. **Distinguish missing values from zeros.** `page_count = 0` might mean a genuinely empty document, a malformed file, or a parser error. If possible, record separate status flags.
3. **Watch for correlated variables.** File size, stream sizes, histogram bins, and entropy statistics overlap statistically. This does not necessarily damage prediction, but complicates feature-level interpretation.
4. **Avoid dataset-source leakage.** If benign PDFs all come from one collection while malicious PDFs come from another, the classifier may learn producer metadata, format versions, or collection practices rather than malicious behavior.
5. **Separate related samples across splits.** Keep duplicates, near-duplicates, modified variants, and related document families out of both train and test at the same time when possible.
6. **Use credible labels.** The presence of `/Launch`, `/OpenAction`, or JavaScript is *not* the ground-truth malicious label.
7. **Measure false positives carefully.** Real-world PDF collections frequently include forms, embedded documents, scanned images, complex filters, and incremental updates.
8. **Calibrate the model's score.** A value in `[0,1]` should not automatically be interpreted as a calibrated probability unless you validate and calibrate it on appropriate held-out data.

### 6.2 Potential future features

Consider adding explicit parser and extraction-status features, if not already implemented:

| Suggested field | Purpose |
| --- | --- |
| `parse_success` | Distinguish a parsed document from a failure to parse |
| `parse_error_count` | Count parser errors encountered |
| `decode_failure_count` | Count streams that could not be decoded |
| `unsupported_filter_count` | Count filters the extractor did not support |
| `truncated_stream_count` | Count streams whose content was incomplete/truncated |
| `parse_recovery_used` | Record whether error-recovery logic was necessary |

These help avoid treating **“not detected because extraction failed”** as equivalent to **“inspected and absent.”**

---

## 7. Extractor semantics to verify before documenting the schema as final

These questions cannot be answered from the column names alone:

| Feature(s) | What to verify in implementation |
| --- | --- |
| `byte_histogram_0`–`255` | Raw count, normalized ratio, or percentage? |
| Entropy block statistics | Block size, overlap/stride, partial-block policy, unit |
| `high_entropy_block_ratio`, `high_entropy_stream_ratio` | Exact threshold and denominator |
| `printable_ratio` | Which bytes count as printable? ASCII range only? |
| `magic_present` | Must `%PDF-` be at offset 0, or is it searched in the file? |
| `version` | Numeric, text, enum, or encoded representation? |
| `object_count`, `reference_count` | Are revisions and repeated objects counted once or repeatedly? |
| `external_host_count` | Distinct hosts or occurrences? How are hosts normalized? |
| `document_javascript_action_count` | Which actions qualify as document-level? |
| `trailing_eof` | Boolean, count, distance, or other metric? |
| `incremental_update_raw_count` | Which byte patterns constitute an incremental update? |
| `filter_depth_*` | Do streams with no filters contribute depth zero? |
| `suspicious_filter_chain_count` | Exact heuristic rules and treatment of unsupported filters |
| `decoded_stream_size_*` | Exclusion or fallback rules when decoding fails |
| `parsed_names_*` | Scope of parsing and whether nested objects are traversed |
| `raw_tokens_*` | Exact tokenization, matching, case/escaping, and scan scope |
| `sample_id` | Is it stable, unique, or content-derived? |

## Conclusion

The displayed Sibilla dataset schema covers 256 byte-histogram features, entropy and file statistics, PDF object structure, scripting/action names, compression and decoding, and parser anomalies. This provides a strong starting point for a **static PDF risk-scoring model**, but the model's usefulness must be demonstrated on carefully split benign and malicious samples and against realistic false-positive rates.

The most important next step is to establish and test an **authoritative schema contract** from the extractor's source code, including missing-data behavior and precise semantics for every derived metric.
