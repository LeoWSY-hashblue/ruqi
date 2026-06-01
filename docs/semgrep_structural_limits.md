# Semgrep Structural Limits

Patterns that semgrep `p/python` and `p/security-audit` cannot catch
regardless of the mapping table. These are inputs to a future v2 design
that adds AST dataflow analysis.

---

## 1. Dispatch-table RCE (dynamic dict-indexed class instantiation)

**Pattern:**
```python
factory   = request.get_json()["llm_factory"]   # user string
model_cls = MODEL_REGISTRY[factory]              # dict lookup
instance  = model_cls(user_args)                 # instantiate from result
```

**Real example:** ragflow `api/apps/llm_app.py` → CVE-2024-10131 (RCE).

**Why semgrep misses it:**
Semgrep matches *syntax*. The dangerous call is `model_cls(...)`, but
`model_cls` is not a known-dangerous identifier — it is the result of a
dict lookup. Semgrep has no way to know that `MODEL_REGISTRY[factory]`
resolves to a callable that performs dangerous operations without:
1. Evaluating the dict definition (cross-file, runtime state)
2. Tracking the value of `factory` backward to user input (cross-function
   taint)

Both require **interprocedural dataflow analysis**, which is outside the
scope of pattern rules.

**Generalisation:** Any "plugin registry", "handler map", or "strategy
dict" where the key is user-supplied falls into this category:
```python
HANDLERS[req_type]()           # HTTP dispatch table
getattr(module, user_method)() # reflection
plugin_map[name].execute(data) # plugin host
```

**v2 fix:** CodeQL / Pysa interprocedural taint tracking, or a custom
semgrep rule that whitelists known-safe registries.

---

## 2. IDOR — access-control logic flaws

**Pattern:**
```python
@router.get("/flows/{flow_id}")
async def get_flow(flow_id: UUID, current_user: User = Depends(get_current_user)):
    flow = await db.get(Flow, flow_id)   # fetches ANY flow by ID
    return flow                           # no ownership check
```

**Real example:** langflow (confirmed IDOR, no CVE published yet).

**Why semgrep misses it:**
There is no dangerous *function call* on any single line. The
vulnerability is the *absence* of an ownership check between the
database fetch and the return. Semgrep rules match patterns that are
present, not patterns that are missing. Detecting "this route fetches an
object but never checks `object.owner_id == current_user.id`" requires:
1. Knowing which routes expose sensitive resources
2. Knowing which fields encode ownership
3. Verifying the check exists somewhere in the call chain

This is a **semantic / policy** property, not a syntactic one.

**Generalisation:** All broken-access-control vulnerabilities share this
structure: a resource is fetched or modified without a policy check. The
check may be absent, bypassed (wrong scope), or misplaced (checked after
side-effect). None of these are detectable by pattern matching.

**v2 fix:** LLM-driven review of each route function ("does this route
check resource ownership before returning?"), or a dedicated access-
control framework that makes ownership checks mandatory at the ORM layer.

---

## 3. Taint-flow SSRF (user-controlled URL in outbound HTTP)

**Pattern:**
```python
@app.post("/fetch")
def proxy(url: str = Body(...)):          # user supplies URL
    resp = requests.get(url, timeout=5)   # fetches it unconditionally
    return resp.content
```

**Real example:** FastChat → CVE-2024-10044 (SSRF).

**Why semgrep misses it:**
The dangerous function (`requests.get`) IS matched by our
`disabled-cert-validation` rule, but only when `verify=False` is passed.
The actual SSRF pattern is `requests.get(user_controlled_url)` with a
valid cert — the cert is fine; the danger is who supplies the URL.

Detecting this requires **taint tracking**: follow the value of `url`
from the HTTP request parameter back through function calls to the
`requests.get` sink. This is what semgrep's *taint mode* (Pro feature)
does, but `p/python` community rules do not include taint sources or sinks
for SSRF.

**Generalisation:** Any outbound HTTP call where the URL (or any component
of it) derives from user input is a potential SSRF, regardless of TLS
validation. The `disabled-cert-validation` rule catches a narrow special
case; the general case requires taint tracking.

**v2 fix:** Semgrep Pro taint rules targeting `requests.get/post/put`
with user-derived URL arguments, or a CodeQL query on the same pattern.

---

## Summary table

| Blind spot | Detection requirement | semgrep OSS | Semgrep Pro taint | CodeQL/Pysa | LLM review |
|---|---|:-:|:-:|:-:|:-:|
| Dispatch-table RCE | Interprocedural dataflow | ✗ | Partial | ✓ | ✓ |
| IDOR / missing auth check | Absence-of-pattern + policy | ✗ | ✗ | Partial | ✓ |
| Taint-flow SSRF | Cross-function taint | ✗ | ✓ | ✓ | ✓ |

**Short-term:** Flag targets with 0 semgrep candidates as "semgrep-blind"
and route to LLM-driven candidate generation instead of silently skipping.

**Long-term (v2):** Add a CodeQL/Pysa pass as a second intake stage for
targets where semgrep returns < 5 candidates.
