# W3 Target Recon Context Template

## Target Metadata

- Target repo: `<repo URL or local path>`
- Target commit: `<commit hash>`
- Target path: `<local checkout path>`
- Framework: `<Flask/FastAPI/Django/Starlette/other>`
- Runtime notes: `<Dockerfile, compose file, startup command, external deps>`
- Semgrep intake status: `<not run / run / failed>`
- LLM: Not run
- Verifier: Not run
- Confirmed findings: 0

## Routing Map

List active HTTP/API/plugin/CLI/background entrypoints. Prefer direct source
evidence over inferred framework behavior.

| Entrypoint | Method / trigger | File | Handler | Auth / permissions | Notes |
| --- | --- | --- | --- | --- | --- |
| TBD | TBD | TBD | TBD | TBD | TBD |

## Upload / URL / File / DB Input Surfaces

List places where users can provide data that may flow into risky sinks.

| Surface | Field / parameter | File | Validation | Storage / rewrite | Notes |
| --- | --- | --- | --- | --- | --- |
| Upload | TBD | TBD | TBD | TBD | TBD |
| URL fetch | TBD | TBD | TBD | TBD | TBD |
| File path | TBD | TBD | TBD | TBD | TBD |
| Database query/filter | TBD | TBD | TBD | TBD | TBD |

## Semgrep Intake Summary

- Candidate count: `<count>`
- RCE: `<count>`
- SSRF: `<count>`
- SQLi: `<count>`
- Path Traversal: `<count>`

| Candidate | File | Line | Sink type | Rule | Symbol | Initial note |
| --- | --- | ---: | --- | --- | --- | --- |
| TBD | TBD | TBD | TBD | TBD | TBD | TBD |

## Selected Code Excerpts

Include only excerpts needed to reason about entrypoints, user-controlled fields,
sanitization, dispatch, and sinks.

```text
<path>:<line>
<excerpt>
```

## Open Questions

- Which entrypoints are active in the default service configuration?
- Which fields are user-controlled before sanitization or rewrite?
- Which sink arguments preserve user-controlled data?
- Which checks are static-only and which require runtime confirmation?
- Is a verifier setup feasible without external paid services?

## Recon Constraints

- Do not write `confirmed`.
- Do not write a CVE-ready conclusion.
- Do not replace static triage or verifier work.
- Do not assume routes, parameters, or framework behavior that is absent from
  the provided context.
