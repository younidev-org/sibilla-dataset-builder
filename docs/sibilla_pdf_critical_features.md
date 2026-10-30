# Sibilla — Most Critical Static PDF Features for Malware Detection

This document prioritizes the fields visible in Sibilla's PDF feature-extraction dataset. The rankings below reflect **security relevance and interpretability**, not statistically validated model feature importance. A feature's presence is **not proof of malware**, and absence does **not prove safety**.

## 1. Highest-priority features

All fields in the table below have the prefix `extraction_format_features_`.

| Priority | Feature suffix | Why it matters |
|---:|---|---|
| 1 | `document_javascript_action_count` | Counts identified JavaScript actions, a direct indicator of script-bearing PDFs. |
| 2 | `parsed_names_Launch` | Identifies launch-action constructs that can request opening files or applications. |
| 3 | `parsed_names_OpenAction` | Identifies actions or destinations associated with document opening. |
| 4 | `parsed_names_AA` | Identifies additional actions associated with events or interactions. |
| 5 | `parsed_names_JS` | Detects the PDF name commonly used to supply JavaScript code. |
| 6 | `parsed_names_JavaScript` | Detects JavaScript action-related names. |
| 7 | `embedded_file_count` | Counts embedded attachments that may carry additional content or payloads. |
| 8 | `suspicious_filter_chain_count` | Counts filter chains flagged by the extractor's own heuristics; verify its exact rules. |
| 9 | `inaccessible_objects` | Measures objects the PDF parser could not access, resolve, or inspect. |
| 10 | `encoded_name_raw_count` | Counts encoded PDF names, which can complicate naive static scanning. |

**Interpretation:** Pay particular attention to **relationships** between scripting, launch/open actions, embedded files, and parser anomalies. Any single count may occur in legitimate PDFs.

## 2. Important supporting features

The first column lists suffixes; add `extraction_format_features_` unless otherwise noted.

| Feature suffix | Why it may be useful |
|---|---|
| `external_uri_count` | Indicates external URI references, potentially including phishing or malicious destinations. |
| `external_host_count` | Characterizes external hosts referenced by the document. |
| `parsed_names_SubmitForm` | May indicate actions that submit form data. |
| `parsed_names_URI` | Indicates URI-related constructs. |
| `duplicate_object_ids` | May identify unusual structures; can also arise from legitimate revisions. |
| `raw_tokens_JavaScript` | Finds JavaScript-related tokens through raw scanning. |
| `raw_tokens_OpenAction` | Finds opening-action tokens through raw scanning. |
| `filter_depth_max` | Measures the deepest stream filter chain. |
| `high_entropy_stream_ratio` | Characterizes the share of streams with high entropy. |
| `xref_stream_count` | Describes cross-reference stream structures. |
| `object_stream_count` | Describes object streams that package PDF objects. |

External links and form-related actions are worth retaining: some harmful PDFs use social engineering or links rather than embedded executable code.

## 3. Lower-priority features *individually*

These features are useful as **statistical context** but are generally less directly interpretable as indicators of malicious behavior:

- `extraction_common_features_byte_histogram_0` through `extraction_common_features_byte_histogram_255`
- `extraction_common_features_size_bytes`
- `extraction_common_features_entropy_global`
- `extraction_common_features_printable_ratio`
- `extraction_common_features_zero_byte_ratio`
- `extraction_format_features_page_count`
- `extraction_format_features_version`
- `extraction_format_features_raw_stream_size_mean`
- `extraction_format_features_decoded_stream_size_mean`

Do **not** discard these just because they are lower priority for human investigation. In a trained model, combinations of statistical and structural features may carry useful predictive information.

## 4. Feature combinations that merit inspection

The following are **illustrative examples**, not reliable decision rules or validated alert thresholds.

### Scenario A — Opening action plus scripting

```text
extraction_format_features_parsed_names_OpenAction = 1
extraction_format_features_parsed_names_JavaScript = 1
extraction_format_features_document_javascript_action_count = 1
```

**What to inspect:** Determine whether the opening action actually targets JavaScript, and examine the action's content through safe static parsing. Token counts alone do not establish that a script executes.

### Scenario B — Embedded files plus parsing anomalies

```text
extraction_format_features_embedded_file_count = 2
extraction_format_features_inaccessible_objects = 4
extraction_format_features_suspicious_filter_chain_count = 1
```

**What to inspect:** Inspect attachments in a controlled, non-executing environment; determine why objects are inaccessible; and validate the rules that classify filter chains as suspicious.

### Scenario C — Ordinary-looking structural measurements

```text
extraction_format_features_page_count = 20
extraction_format_features_stream_count = 45
extraction_format_features_filter_counts_FlateDecode = 30
extraction_format_features_parsed_names_JavaScript = 0
```

**What this means:** These fields show no obvious scripting indicator, but **do not prove that the file is benign**. Legitimate and malicious documents can share the same high-level statistics.

## 5. Recommended model-development workflow

For a dataset containing approximately **10,000 benign and 5,000 suspicious PDFs**, a defensible first experimental workflow is:

1. **Retain all available numeric features** and train a baseline LightGBM or XGBoost model.
2. **Validate labels**: distinguish confirmed malicious, confirmed benign, and uncertain samples; avoid treating uncertain files as known malware.
3. **Prevent leakage**: group near-duplicates, related documents, and variants across train/validation/test splits; consider a held-out time-separated dataset.
4. **Measure feature importance** using permutation importance on held-out data, alongside model-native importance if desired.
5. **Run ablation experiments** comparing the top 10, top 20, top 50, and full feature sets; determine the ranking from your data rather than from this document.
6. **Compare appropriate metrics**: malicious recall, benign false-positive rate, precision–recall AUC, and inference time. Avoid relying on accuracy alone.
7. **Verify extractor definitions**: especially `suspicious_filter_chain_count`, `inaccessible_objects`, `encoded_name_raw_count`, counting semantics, missing values, and the handling of decoding errors.

### Practical limitation of the current feature set

Your current fields generally describe **whether an action, token, attachment, or structure exists**, rather than its complete semantics. They do not necessarily reveal:

- What JavaScript actually does.
- Whether an `OpenAction` points to JavaScript, navigation, or something else.
- Where an external URI points, or whether a destination is malicious.
- What is inside an embedded file.
- Whether a viewer would perform the requested action.

For catching threats missed by signature-based antivirus, **safe and bounded static inspection of action targets, scripts, URLs, and embedded content** may add more value than additional generic byte statistics. Avoid executing sample content during feature extraction.

## 6. Bottom line

**Prioritize analysis of JavaScript and actions, embedded files, suspicious decoding structures, and parser anomalies. Keep the full feature set for initial model training.** Only held-out evaluations can establish which features materially improve detection accuracy, recall, false-positive rate, and generalization.
