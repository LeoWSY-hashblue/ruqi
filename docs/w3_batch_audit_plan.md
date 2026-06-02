# W3 Batch Audit Plan

## Current Pipeline Status

### W0/W1/W2 Completed

- W0/W1 established the repository workflow, Semgrep intake path, and candidate
  data model needed to turn static sink hits into auditable candidate records.
- W2 added a deterministic dynamic verifier for RCE candidates.
- W2 verifier outcomes are independent from LLM output:
  - `confirmed`: PoC succeeds and canary is deleted or modified.
  - `suspected`: PoC succeeds but canary remains unchanged.
  - `false_positive`: PoC fails or the candidate type is unsupported.
- W2 verifier uses canaries planted and read inside the target container via
  `docker exec`.
- W2 includes unit coverage and Docker-based e2e fixture coverage.

### gpt_academic Negative Audit

- `gpt_academic` was used as the first real target for a static audit pass.
- Semgrep intake produced two RCE candidates:
  - C1: `compile_latex_with_timeout(command, shell=True)`.
  - C2: `convert_to_markdown(file_path)`.
- C1 result: `likely false positive`.
  - Active LaTeX plugin flow reaches `shell=True`.
  - Static review did not prove that user-controlled shell metacharacters enter
    the observed command strings.
- C2 result: `likely false positive / unreachable`.
  - Sink exists and would be unsafe if reachable.
  - No active registered UI/plugin route was found.
- Final audit result:
  - Confirmed findings: 0
  - CVE-ready findings: 0
  - Dynamic verifier: not run, because no exploitable path was proven.

## W3 Goal

- Batch-audit 5-10 Python open-source projects.
- Find at least 1 candidate with enough static evidence to enter verifier work.
- Prefer candidates where the path from active HTTP/API/plugin entrypoint to sink
  is short, observable, and reproducible.

## Target Selection Criteria

- Python Web/API project.
- Active HTTP/API route or plugin entrypoint is clear from source.
- User input reaches one of these sink categories through a short path:
  - RCE
  - SSRF
  - SQLi
  - Path Traversal
- Project has a Dockerfile or is easy to containerize.
- The target can be run locally without paid services or complex external state.
- A minimal PoC can be expressed as HTTP/API calls, file upload, or a small local
  script against the target service.

## Exclusion Criteria

- UI-only or library-only project with no active service route.
- Sink is primarily in downstream user code, examples, or integration snippets.
- Semgrep only hits migrations, tests, generated files, maintenance scripts, or
  unreachable utility functions.
- Active route is unclear after a short static review.
- Project requires hard-to-reproduce external infrastructure before the sink path
  can be exercised.
- Candidate depends on a real LLM decision before basic reachability can be
  established.

## Candidate Triage Checklist

For each Semgrep candidate, answer these before LLM or verifier work:

- Active entrypoint?
  - Which HTTP route, API method, CLI command, plugin registration, or background
    task invokes the vulnerable code?
- User-controlled field?
  - Which request parameter, uploaded file path, JSON field, header, URL, or
    database value is controlled by the attacker?
- Sink argument preserves taint?
  - Does the controlled value reach the dangerous argument without being replaced
    by a generated constant or safe lookup result?
- Sanitization/path rewrite?
  - Is there validation, escaping, allowlisting, path normalization, copy-to-temp,
    or canonicalization that removes attacker control?
- Dynamic verifier feasible?
  - Can the target run in Docker?
  - Can the PoC be executed deterministically?
  - Can the verifier observe a canary, HTTP response, filesystem change, or
    network request that distinguishes true exploitability from a crash?

## W3 Execution Batch Format

Use one row per target and update it after each triage phase.

| Target repo | Commit | Semgrep candidate count | Triage result | LLM needed? | Verifier needed? | Final status |
| --- | --- | ---: | --- | --- | --- | --- |
| TBD | TBD | TBD | TBD | TBD | TBD | TBD |

Recommended per-target notes:

- Candidate IDs and sink types.
- Active entrypoints found.
- Rejected candidates and rejection reasons.
- Candidate selected for deeper review.
- Required runtime services or Docker notes.
- Whether verifier input is ready.

## Recommended Next Batch Selection Method

1. Start from known Python web apps, AI agent tools, automation servers, and
   file-processing services.
2. Prefer projects with obvious route definitions and simple local startup.
3. For each target, record the exact commit before scanning.
4. Run Semgrep intake first.
5. Do not call LLM immediately.
6. Fill the candidate triage checklist from source evidence.
7. Use LLM only for bounded call-chain reconstruction when static context is
   compact and the active route is plausible.
8. Enter verifier work only after static triage identifies a concrete route,
   user-controlled field, and sink argument preserving taint.

## LLM Reconnaissance Track

LLM reconnaissance is an optional static-review aid for targets where Semgrep
intake is empty, noisy, or misses framework-specific dispatch behavior. It must
not replace deterministic static triage or verifier work.

LLM recon purpose:

- Identify active HTTP/API/plugin entrypoints.
- Find structural Semgrep blind spots such as SSRF dataflow, dispatch-table RCE,
  IDOR, and path traversal patterns.
- Suggest candidate source-to-sink paths for human triage.
- Help prioritize which files and routes should be read next.

LLM recon prohibitions:

- Do not write `confirmed`.
- Do not produce a CVE-ready conclusion.
- Do not replace verifier or equivalent deterministic evidence.
- Do not assume routes, parameters, permissions, or framework behavior not
  present in the provided context.

LLM recon output requirements:

- Every suspected path must enter the static triage checklist before any deeper
  work.
- Classifications are limited to `recon candidate`, `needs static check`, or
  `likely irrelevant`.
- Missing context must be listed explicitly.
- Dynamic verification remains `Not run` until the verifier is intentionally
  invoked in a later phase.

## W3 Completion Criteria

- 5-10 targets reviewed with reproducible triage notes.
- At least 1 candidate selected for verifier preparation, or a documented reason
  why no candidate in the batch met verifier-entry criteria.
- No CVE report is drafted unless verifier or equivalent deterministic evidence
  confirms exploitability.
