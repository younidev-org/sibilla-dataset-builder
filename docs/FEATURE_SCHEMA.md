# Extraction schema (development)

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

Still pending: remaining structural/active-content features, decoded stream
statistics, complete fixed table schema, and schema compatibility validation.
The lopdf decompression limit applies per decoded stream, not to aggregate document
expansion; worker address-space limits provide an additional ceiling.
