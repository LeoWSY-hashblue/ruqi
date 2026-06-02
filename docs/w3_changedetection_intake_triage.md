# W3 changedetection.io Semgrep Intake Triage

## Target

- Target repo: `https://github.com/dgtlmoon/changedetection.io`
- Target path: `E:\tool\targets\changedetection.io`
- Target commit: `dd56a502c0b3d025a6a1d4e46942e9321b977bf8`
- Target status: clean
- LLM: Not run
- Verifier: Not run
- Confirmed findings: 0

## Semgrep Intake Summary

- Semgrep candidate count: 0
- Candidate type distribution:
  - RCE: 0
  - SSRF: 0
  - SQLi: 0
  - Path Traversal: 0

## Candidate Table

No candidates were produced by Semgrep intake for the configured W3 rules.

| Index | File | Line | Sink type | Rule | Enclosing symbol | Code snippet first 8 lines |
| ---: | --- | ---: | --- | --- | --- | --- |

## Initial Triage Checklist

- active entrypoint?: No candidate to evaluate.
- user-controlled field?: No candidate to evaluate.
- sink argument preserves taint?: No candidate to evaluate.
- sanitizer/path rewrite?: No candidate to evaluate.
- verifier feasible?: Not applicable at intake stage.

## Notes

- changedetection.io was cloned through the local proxy at `127.0.0.1:6789`.
- `.semgrep` state was cleaned from the target checkout after intake.
- No LLM-assisted call-chain reconstruction was run.
- Dynamic verifier was not run.
- Confirmed findings remain 0.
- SSRF-related candidates were 0. This should be interpreted as no SSRF match
  from the current W3 Semgrep intake rules, not as evidence that the project has
  no SSRF risk.
