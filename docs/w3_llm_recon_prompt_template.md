# W3 LLM Recon Prompt Template

## Purpose

Use this prompt only for bounded static reconnaissance. The model must identify
candidate paths for human review. It must not produce a confirmed finding or a
CVE-ready conclusion.

## Input

### Target Repo

`<target repo URL or local path>`

### Commit

`<target commit hash>`

### Framework / Routing Files

List files that define routes, APIs, plugin registration, background task
dispatch, CLI commands, or webhook handlers.

```text
<path>: <short reason it matters>
```

### Selected Source Excerpts

Provide only source excerpts needed to reason about entrypoints, input parsing,
dispatch, sanitization, and sinks.

```text
<path>:<line>
<excerpt>
```

### Semgrep Candidate Summary

```text
candidate_count: <count>
type_distribution: <RCE/SSRF/SQLi/Path Traversal counts>
top_candidates:
- <candidate id>: <file>:<line> <sink_type> <rule> <symbol>
```

## Instructions

Analyze only the provided context. Do not infer routes, parameters, permissions,
or framework behavior that is not present in the input.

Identify possible paths where user-controlled input may reach security-relevant
sinks. Treat all paths as unconfirmed reconnaissance candidates until static
triage and verifier work prove otherwise.

Do not write `confirmed`. Do not write a CVE-ready conclusion. Do not replace
verifier work.

## Output Schema

```json
{
  "entrypoints": [
    {
      "name": "<route or handler>",
      "file": "<path>",
      "line": "<line or unknown>",
      "input_sources": ["<request parameter/upload/url/path/db field>"],
      "classification": "recon candidate | needs static check | likely irrelevant",
      "evidence": "<source-based evidence>"
    }
  ],
  "user_controlled_sources": [
    {
      "source": "<field or object>",
      "entrypoint": "<entrypoint>",
      "constraints": "<validation, auth, type conversion, or unknown>"
    }
  ],
  "sink_families": [
    {
      "family": "RCE | SSRF | SQLi | Path Traversal | Other",
      "files": ["<path>"],
      "notes": "<sink shape and constraints>"
    }
  ],
  "suspected_paths": [
    {
      "path_id": "<id>",
      "source": "<source>",
      "sink": "<sink>",
      "call_chain": ["<file:function or route step>"],
      "classification": "recon candidate | needs static check | likely irrelevant",
      "why": "<brief source-based rationale>",
      "missing_context": ["<specific missing file/function/route>"]
    }
  ],
  "semgrep_blind_spots": [
    {
      "pattern": "<dispatch-table RCE, SSRF dataflow, IDOR, path traversal, etc>",
      "reason": "<why Semgrep may miss it>",
      "files_to_review": ["<path>"]
    }
  ],
  "required_static_checks": [
    "<specific source check required before verifier>"
  ],
  "verifier_feasibility": {
    "status": "not assessed | feasible | blocked | not applicable",
    "reason": "<reason>",
    "required_setup": ["<docker/service/data setup>"]
  },
  "confidence": "low | medium | high"
}
```

## Classification Limits

Allowed classification values:

- `recon candidate`
- `needs static check`
- `likely irrelevant`

Forbidden outputs:

- `confirmed`
- `CVE-ready`
- Any final vulnerability verdict.
