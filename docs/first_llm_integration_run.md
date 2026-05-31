# First LLM Integration Run — flask-admin SQLi Candidate

**Date:** 2026-05-31
**Model:** gpt-4o (via lingyaai proxy, OpenAI-compatible endpoint)
**Flag:** `python -m vulnhuntr -r audit_targets/flask-admin --semgrep -l gpt`
**Candidate:** `flask_admin/contrib/sqla/ajax.py:112` · sink_type=`sqli`

---

## Run summary

| Metric | Value |
| - | - |
| Secondary rounds | **2** (i=0, i=1) |
| Context items requested at i=0 | 3 |
| Context items fetched at i=1 | 3 |
| Context items requested at i=1 | 0 → normal termination |
| abort_reason | `None` (clean exit) |
| Final confidence_score | **9 / 10** |
| Total rough token estimate | ~6 500 |

---

## Context items requested by LLM

At round i=0 the LLM requested three additional symbols:

| name | reason |
| - | - |
| `QueryAjaxModelLoader.__init__` | "Understanding how 'fields' and 'filters' are provided during initialization is essential to analyze their trustworthiness." |
| `QueryAjaxModelLoader.get_query` | "Determines how the SQLAlchemy query object is constructed before filtering." |
| `QueryAjaxModelLoader._process_fields` | "Handles preparation and validation of the 'fields' object." |

After seeing those at i=1, the LLM returned `context_code=[]` — it felt it had a complete enough picture of the call chain.

---

## LLM final analysis (verbatim)

> The `get_list` method in `QueryAjaxModelLoader` is vulnerable to SQL Injection
> through two key points.
>
> **1.** The `term` parameter is incorporated into SQL `ilike` filters without any
> sanitization or escaping. The function dynamically applies filters using
> SQLAlchemy's `or_()`.
>
> **2.** `self.filters` can introduce raw SQL strings via the `text` function,
> dynamically appended to the query filter logic, allowing attackers to inject
> arbitrary SQL commands.
>
> Both pathways are remotely exploitable in network-exposed instances.

**LLM PoCs:**

```
1. GET /api/ajax_loader?term=' OR 1=1--
2. Craft a malicious filter: {'filters': ['id; DROP TABLE users--']}
```

---

## Human review: false-positive analysis

### Vector 1 — `term` → `.ilike(f"%{term}%")` — **FALSE POSITIVE**

SQLAlchemy's `.ilike()` is an ORM expression builder, not string concatenation.
Under the hood it emits a parameterized query (`ILIKE %s` with the value bound
separately). The `f"%{term}%"` is the pattern argument to `ilike`, which
SQLAlchemy then binds as a parameter — `term` never touches raw SQL text.

The LLM mistook ORM expression chaining for raw SQL string interpolation. This
is a systematic weakness: the model pattern-matches on `f"...{term}..."` and
flags it as unsafe regardless of what function it's passed to.

**Verdict: false positive. PoC #1 will not work.**

### Vector 2 — `self.filters` → `text(f"{...}.{value}")` — **LOW RISK / UNLIKELY**

This is the pattern semgrep originally flagged. The LLM correctly identified
that `text()` is raw SQL. However the data-flow analysis has a gap:

- `self.filters` is set via `options["filters"]` in `__init__`
- `options` is passed by the Flask-Admin **developer** at class-definition time
  (e.g. `form_ajax_refs = {'user': {'filters': ['status = active']}}`)
- It is NOT derived from the AJAX HTTP request body or URL parameters

For this to be exploitable an attacker would need to control the server's Python
source (the admin class definition), which is not a remote-exploitation scenario.

**Verdict: low-risk configuration pattern, not a remotely exploitable SQLi.
PoC #2 is incorrect — `filters` is not an HTTP parameter.**

### Overall verdict: **likely false positive, confidence 2/10 for real exploitation**

---

## Token estimate (rough)

| Phase | Input tokens | Output tokens |
| - | -: | -: |
| i=0: FileCode + enclosing_source + prompt templates | ~2 500 | ~350 |
| i=1: same + 3 context items (~200 tok each) | ~3 100 | ~380 |
| **Total** | **~5 600** | **~730** |

Rough total: **~6 300 tokens** for this run (~$0.019 at gpt-4o pricing).

---

## What the run tells us for W2

### Positive signals

1. **End-to-end pipeline works.** Semgrep → Candidate → secondary loop → LLM
   verdict completes without errors in 2 rounds.
2. **Context fetching works.** LLM correctly identified and requested the three
   methods needed to understand the data flow.
3. **Hard limits not needed.** 2 rounds and clean exit — the loop termination
   logic behaves correctly.

### Problems to address before W2

| Problem | Impact | Fix |
| - | - | - |
| LLM doesn't distinguish ORM parameterized calls from raw SQL concatenation | High false-positive rate on SQLAlchemy targets | Add ORM awareness note to system prompt or SQLI vuln prompt |
| LLM treats developer-configured fields as user-controlled HTTP input | Incorrect exploitability claim for `self.filters` | System prompt: "developer-configured options are NOT user HTTP input" |
| Confidence 9 on a likely-false-positive finding | Distorted W2 prioritization | Calibrate: don't automatically trust high confidence scores without call-chain proof |

### Recommendation for first W2 dynamic verification target

**Do NOT start with this flask-admin SQLi candidate.** It is almost certainly a
false positive (ORM parameterized calls). Dynamic verification would waste time
confirming non-exploitability.

Better first W2 target: a repo that uses **`eval()` or `subprocess(shell=True)`
with user-supplied strings** — patterns where the LLM's false-positive risk is
much lower and dynamic RCE verification (container canary file) is unambiguous.

Run `run_semgrep_intake.py` on a project like
`gpt-researcher` or `ragflow` (both had confirmed vulns per vulnhuntr's own
README) to get higher-quality initial candidates before investing in W2
infrastructure.
