# Dataset protocol

[< Back to Sibilla Dataset Builder](../README.md) • [Documentation Hub](README.md)

Input tables must exactly match the current Arrow/CSV schema, PDF format, schema
version and extractor version. Labels must be 0, 1 or null; digests use lowercase
SHA-256 hex. Unknown labels and unavailable extraction results are excluded.
Exact duplicates retain one feature row. Contradictory known labels error or
quarantine the entire identity, including conflicting failed records with a hash.
Conflicting group memberships for a duplicate identity are rejected.

Groups are deterministically ordered by SHA-256 of the seed and group key, then
allocated as whole units using class-balance targets. This is a balancing heuristic:
large groups and small classes cannot necessarily achieve exact requested ratios.
Without a group column, each exact identity is its own group. Neither near-duplicate
leakage nor family leakage is detected automatically. Temporal evaluation is not
available because this schema has no defensible first-seen timestamp field.

The manifest preserves metadata separately from predictive columns. `sample_id`
is retained as a join key in feature/split tables and must be removed from model
inputs. Reports include duplicates, conflicts, excluded counts, null rates and
class counts per split. Metadata records seed, strategy and artifact hashes.
Output publication refuses an existing destination and uses Linux no-replace rename.
