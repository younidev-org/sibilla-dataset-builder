# Extraction schema (development)

[< Back to Sibilla Dataset Builder](../README.md) • [Documentation Hub](README.md)

`pdf-v1` is not frozen until output and all specified PDF features are complete.

Byte statistics use all input bytes; entropy is Shannon bits/byte. Block statistics
use 4096-byte chunks including the final short chunk, population standard deviation,
and high entropy means strictly greater than 7.5 bits/byte. Empty input yields zero
for byte statistics. Histograms contain 256 normalized entries in byte order.
ASCII is 0–127; printable is 32–126. SHA-256 is identity metadata, never predictive.

Raw token counts count byte substrings, including strings, comments and streams;
parsed-name counts include matching dictionary keys and name values in loaded
objects. They do not establish action reachability or malicious behavior.
Malformed PDFs retain byte statistics and raw counts; unavailable semantic fields
remain null. Oversized inputs have no invented byte statistics. PDF magic must
begin within the first 1024 bytes. Page counts come from lopdf's page tree.

Structural fields now include reference/loaded stream/object-stream counts,
catalog/metadata/AcroForm key presence, embedded-file and Filespec typed-object counts,
URI-string count and canonical distinct hosts, raw/decoded stream size statistics,
filter depth and filter counts, high-entropy stream ratio and raw update/encoded-name
candidates. URI parsing is lexical and never performs network requests. Raw encoded
name candidates count #XX escapes in byte tokens and may include text content.

Stream statistics include all loaded streams, including XRef streams. Missing and
empty filter chains mean identity decoding. Explicit decoding shares the aggregate
budget across streams. Unsupported filters or budget exhaustion leave decoded
statistics null and mark extraction partial. Typed object counts cover loaded objects
with an explicit /Type; they are not a claim about all historical revisions.

Password-required encryption preserves byte/raw features and encrypted=true, with
semantic fields null. Empty-password encryption is still flagged after decryption.

Currently unsupported measurements remain null: total historical XRef-table count
(lopdf merges tables), duplicate IDs and inaccessible object counts (the loaded map
cannot recover discarded objects), document-level JavaScript and catalog action
reachability (graph traversal is not implemented). Embedded-only size summaries and
complete revision/action graph features remain pending.

Quality columns include parse status, failure stage, error code and extraction
status. Header/magic presence is null when byte features are unavailable, rather
than false. Typed readers reject incompatible schemas and nonfinite numbers.
The lopdf decompression limit applies per decoded stream, not to aggregate document
expansion; worker address-space limits provide an additional ceiling.

The field list is defined in `sibilla-b-schema` and the flattened Arrow schema in
`sibilla-b-output`. Histograms are `extraction_common_features_byte_histogram_000`
through `_255`. Count columns are nullable Int64; measurements Float64; presence
flags Boolean. CSV null is `\N`, with leading string backslashes escaped.
