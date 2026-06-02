# W3 ArchiveBox Semgrep Intake Triage

## Target

- Target repo: `https://github.com/ArchiveBox/ArchiveBox`
- Target path: `E:\tool\targets\ArchiveBox`
- Target commit: `00cf5c9dd04775af13f00aed6ae15d63d9c3a6bd`
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

- ArchiveBox clone succeeded through the local proxy at `127.0.0.1:6789`.
- `.semgrep` state was cleaned from the target checkout after intake.
- No LLM-assisted call-chain reconstruction was run.
- Dynamic verifier was not run.
- Confirmed findings remain 0.
