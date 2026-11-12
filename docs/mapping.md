# Mapping file (schema version 1)

The mapping is yours. `inspect-oscal mapping init` prints the default; unknown keys are rejected.
`inspect-oscal mapping check FILE` confirms every target exists in the pinned catalog (oscal-cli does
not check this).

```yaml
version: 1
catalog: nist-ai-rmf-1.0        # only value accepted
statement: derived              # printed into every output
rules:
  - id: security-evals          # stable; part of the uuid seed
    match:
      any:                      # or `all: [..conditions..]`, or `all: true` (every log)
        - task_glob: ["*cyber*"]
        - tags: [security]
    targets: [MEASURE_2.7]      # subcategory or category ids
    scores:
      - {scorer: "*", metric: accuracy, threshold: {op: ">=", value: 0.70}}
    require_complete: true      # default true: also needs every sample scored; false relaxes only that
  - id: tevv
    match: {all: true}
    targets: [MEASURE_2.1]
    observe: {kind: log-facts}  # dataset, scorers, packages, git revision; never a finding
```

Condition keys (all given keys must match; list values match if any item does, globs are
case-insensitive): `task_glob`, `task_registry_glob`, `tags` (spec tags plus log tags), `dataset_glob`,
`model_glob`, `metadata: {key: value}`.

Scores: `scorer` and `metric` are globs against the log's score and metric names; `reducer` optional.
`threshold.op` is one of `>= > <= < ==`; use `<=` for lower-is-better metrics.

Case rules: task, registry, dataset and model globs are case-insensitive; `scorer` and `metric` globs
are case-sensitive. Threshold values must be finite numbers.

A threshold is your judgement. Every thresholded metric gets a `threshold-result` property on its
observation (`met`, `missed`, `not-evaluated`). With `--findings` the tool also writes a finding per
target subcategory: `satisfied` when every matched thresholded metric met its threshold, `not-satisfied`
when any missed; the finding names each metric and reducer. These states record the threshold result
only and are not a determination about the subcategory.

Nothing is evaluated for incomplete runs (status other than `success`), absent or NaN metrics, or when
abnormal scores were found, or the log lacks total and completed sample counts or has
`completed != total` (whatever `require_complete` says). `require_complete` (default `true`)
additionally needs a scored-sample count of at least the total; set it to `false` only to allow
unscored samples.
