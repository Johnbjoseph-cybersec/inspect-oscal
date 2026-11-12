# inspect-oscal

Unofficial. Converts [Inspect](https://inspect.aisi.org.uk/) eval logs into
[OSCAL](https://pages.nist.gov/OSCAL/) assessment-results, so GRC teams can exchange eval results as
evidence against NIST AI RMF 1.0 subcategories.

**This tool produces evidence, not a verdict.** The mapping from evals to subcategories is derived by
you (a starting file ships, and you are expected to edit it). It is not NIST-endorsed. By default the
output is observations only: measured values, each with a `threshold-result` property
(`met`, `missed` or `not-evaluated`) when your mapping declares a threshold.

OSCAL findings are opt-in (`--findings`). OSCAL requires a finding's `target.status.state` to be
`satisfied` or `not-satisfied`, and those are the only usable values. When you enable findings, **the
state records only whether your declared threshold was met on that evidence. It is not a determination
that the subcategory is satisfied**, and every finding says so in its description and in a
`status-meaning` property. Tools that display the status field without the description will show those
words, so enable findings only if your consumers know this.

## What it does

- Reads `.eval` and `.json` logs with `inspect_ai`'s `read_eval_log` (local paths or fsspec URLs).
- Maps tasks and scores to NIST AI RMF subcategories through a user-editable YAML mapping file.
- Writes an OSCAL assessment-results bundle: results, plus the assessment plan, SSP and profile that
  OSCAL validators require, and the pinned NIST catalog.
- Records each log's SHA-256 (of the exact bytes parsed) as evidence in the back-matter. Inspect logs
  carry no hash of their own.
- Records aggregates and names. No prompts, outputs or sample text enter the OSCAL files; task,
  dataset and model names, eval ids and scorer names (your strings) do. Sample reading only counts
  abnormal scores.
- Evidence links are a bare file name, or the `--evidence-base-url` you give (a relative label or a
  URL). Absolute and `file://` paths, URL userinfo, queries and fragments are never written; an
  absolute local path or `file://` URL is rejected as a base. The same redaction (one shared helper)
  is applied to every error message and warning, so a failing signed URL never prints its password
  or token.
- Declares OSCAL **1.2.1** by default for compliance-trestle compatibility (`--oscal-version` overrides).
- Output is deterministic: UUIDs are uuid5 of stable inputs, and `--now` or `SOURCE_DATE_EPOCH` fixes
  the clock.

## Install

```
pip install inspect-oscal          # Python 3.11 to 3.13; not yet on PyPI
```

## Example

```
inspect eval tiny_cyber_task.py --model mockllm/model --log-dir logs      # produce a log
inspect-oscal mapping init > mapping.yaml                                 # a copy you own
inspect-oscal mapping check mapping.yaml                                  # targets exist in the catalog
inspect-oscal convert logs/*.eval -o oscal-out --mapping mapping.yaml     # write the bundle
inspect-oscal convert logs/*.eval -o oscal-out --mapping mapping.yaml --findings   # opt in to findings
inspect-oscal validate oscal-out --oscal-cli /path/to/oscal-cli           # integrity + schema
```

A task, two real logs (one `.eval`, one `.json`, made with `mockllm`) and the resulting bundle are in
`examples/`. `examples/bundle/` is default output (observations only, no `--findings`) and includes the
pinned catalog, so it validates as shipped (`inspect-oscal validate examples/bundle`). Regenerate it from
the repository root; a test checks that this reproduces it byte for byte:

```
inspect-oscal convert examples/logs/*.eval examples/logs/*.json -o examples/bundle \
  --mapping examples/mapping-with-thresholds.yaml \
  --system-name "Example claims assistant" --now 2026-11-12T12:00:00Z
```

```python
from inspect_oscal import convert_logs, load_mapping, validate_bundle

bundle = convert_logs(
    ["logs/run.eval"],
    out_dir="oscal-out",
    mapping=load_mapping("mapping.yaml"),
    system_name="Claims triage assistant",
)
report = validate_bundle("oscal-out", use_oscal_cli=True)  # ValidationReport(ok, errors, warnings)
```

## Output

```
oscal-out/
  assessment-results.json   observations per matched score, findings only with a threshold
  assessment-plan.json      reviewed controls = the mapped subcategories
  ssp.json                  placeholder system record (--system-name)
  profile.json              imports the pinned catalog, selects the mapped subcategories
  NIST_AI-RMF_v1_catalog.json   unmodified NIST catalog, hash-checked
  MANIFEST.json             SHA-256 of each file, tool version, mapping hash
```

oscal-cli cannot validate a lone assessment-results file; it resolves the whole chain, hence the
bundle. Custom properties use the namespace
`https://github.com/Johnbjoseph-cybersec/inspect-oscal/ns/1.0`.

| OSCAL field | Meaning here |
|---|---|
| observation | one measured value (task, scorer, metric, value, sample counts, log status) matched by a rule; or a "log facts" record |
| observation prop `threshold-result` | `met` / `missed` against your threshold, or `not-evaluated` (with `threshold-note` giving why). Always present when a threshold is declared |
| finding (only with `--findings`) | `satisfied` / `not-satisfied` = your threshold was met / missed on that evidence. Not a determination about the subcategory |
| no threshold result or finding | no threshold declared, run not `success`, metric absent or NaN, abnormal scores found, sample counts missing from the log, or `completed != total` (always, whatever the mapping says), or (with `require_complete`, which defaults to **true**) scored samples fewer than total. Never inferred as a pass |
| back-matter resource | the Inspect log, with its SHA-256 |

When several scorers or reducers match one thresholded entry, every matched metric must meet its
threshold; a finding names each one (including the reducer). Abnormal scores are detected by reading
samples, which is the default; `--no-samples` skips that (and says so in the output) for very large
logs. The whole log is read into memory (default cap 1 GiB).

## Validation

`inspect-oscal validate` runs three layers. It runs whatever `oscal-cli` it finds (`--oscal-cli`,
`INSPECT_OSCAL_CLI`, then `PATH`) with a timeout, so only point it at a binary you trust.

1. `oscal-cli` (3.2.0, OSCAL 1.2.1 bindings, needs Java 17+) over results, plan, SSP and profile.
2. Reference integrity, which oscal-cli does **not** do: every control id and target id exists in the
   pinned catalog, every uuid reference resolves, uuids are unique, every observation links evidence
   carrying a SHA-256, and the manifest hashes match. The manifest sits beside the files it covers, so it
   detects accidental change only; it is not tamper-proof (use detached signing if you need that).
   Malformed documents are reported as INVALID, not as a crash.
3. A wording lint over the text this tool writes (not your task or model names): it flags words such as
   "compliant", "certified", "conforms" and "passed". It is a guard against careless wording, not an
   assurance of anything.

The catalog itself is hash-pinned, not re-validated: NIST's own catalog trips two
`oscal-unique-link-in-context-location` constraints in oscal-cli 3.2.0.

`convert` checks its own output with layer 2 before writing anything, and warns when it overwrites a
previous bundle. The same run supplied twice (identical bytes, or the `.eval` and `.json` of one eval_id)
is converted once. When two inputs share an eval_id (for example after `inspect score` rewrote a log),
the most recently modified local file wins (a file with a known modification time beats a URL; ties go
to `.eval`, then the lowest hash). The warning names both files, says which was kept and why, and says
whether their contents differ (expected for a `.eval`/`.json` pair; re-scored or edited logs also differ). Modification time alone decides, which is not the same as "latest scoring": a freshly re-exported `.json` beats the original `.eval`. Pass only the log you want if you need a different choice. All identifiers are seeded from the log's SHA-256.

Exit codes: 0 ok, 1 usage or IO, 2 `--strict` warnings, 3 validation failure.

Tested with `inspect-ai` 0.3.289 (the floor and the only version run); the dependency range is
`>=0.3.289,<1`.

## The mapping

See [docs/mapping.md](docs/mapping.md). The default ships with no thresholds, so it writes
observations only.

## Licence

MIT (see `LICENSE`). The bundled NIST AI RMF OSCAL catalog (usnistgov/oscal-content v1.6.0) is a US
government work, public domain and CC0 1.0; see `src/inspect_oscal/data/NIST_LICENSE.md`,
`SOURCE.md` and `SHA256SUMS`. NIST does not endorse this project or its mapping. "Inspect" is the UK
AI Security Institute's evaluation framework; this project is not affiliated with it.

Author: John B Joseph, Co-founder & CPTO, Purplecop Security.
