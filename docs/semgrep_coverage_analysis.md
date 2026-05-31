# Semgrep Coverage Analysis

This document tracks the structural limits of semgrep pattern matching as discovered
during real audits. Entries here inform decisions about when to supplement or replace
semgrep with deeper analysis techniques.

---

## ragflow blind spot

**Target:** infiniflow/ragflow  
**Known CVE:** CVE-2024-10131 (RCE, confirmed by vulnhuntr)  
**Semgrep result:** 0 candidates from mapping table on `p/python` or `p/security-audit`

### The pattern semgrep cannot catch

The ragflow RCE lives in `api/apps/llm_app.py`, in the `add_llm` route:

```python
# Simplified from the actual code
factory = req['llm_factory']          # user-controlled string
llm_name = req['llm_name']            # user-controlled string

# Dynamic class lookup + instantiation from user-supplied key
model_class = EmbeddingModel[factory]
instance = model_class(llm_name, api_key, ...)
```

`EmbeddingModel` is a dict whose values are class references. The user supplies
`factory` as an HTTP request field, which is used as the dict key to select and
then **instantiate** a class. If `factory` resolves to a class that executes
arbitrary code on construction, or if the dict can be polluted, this is RCE.

### Why semgrep pattern matching cannot catch this

Semgrep works by matching **syntactic patterns** in a single file or a small AST
context. It can reliably catch:

- Direct dangerous calls: `eval(x)`, `exec(x)`, `subprocess.Popen(..., shell=True)`
- String formatting into dangerous sinks: `text(f"...{user_val}...")`
- Known-dangerous API calls with known argument positions

The ragflow pattern fails all three tests:

1. **No direct dangerous function call.** The sink is `SomeClass.__init__()` reached
   via `dict[user_key]()`. There is no `eval`, `exec`, or `subprocess` on the line.

2. **Multi-step data flow across file boundaries.** The exploit path is:
   `HTTP request body → req['llm_factory'] → EmbeddingModel[factory]` where
   `EmbeddingModel` is defined in a different module. Semgrep's taint tracking
   would need to follow this cross-file reference, which `p/python` rules do not do.

3. **The danger is in the dict's contents, not the dict lookup itself.**
   `d[user_key]()` is syntactically identical whether `d` contains safe callables or
   dangerous ones. Semgrep has no way to know what values `EmbeddingModel` holds
   without evaluating the full module graph.

### This is a structural semgrep limitation, not a mapping table gap

Adding more rules to `SEMGREP_RULE_TO_SINK` cannot fix this. The pattern is
simply outside the expressive power of lexical/AST pattern matching:

- Pattern matching catches **known-dangerous APIs at known call sites**.
- This vulnerability uses **an indirect, user-steered call through a data structure**
  where the danger is in the semantics of the data, not the syntax of the call.

The same blind spot applies to any "dispatch table" or "plugin registry" pattern:
```python
HANDLERS[user_input]()           # user selects which function to call
getattr(module, user_input)()    # user selects method by name
plugin_registry[user_input].run(data)
```

Semgrep `p/python` and `p/security-audit` will miss all of these.

### What would catch it

| Technique | Can catch this? | Cost |
|-----------|:--------------:|------|
| Semgrep pattern rules | No | — |
| Semgrep taint mode (Pro) | Partially — needs cross-file taint | Medium |
| AST + dataflow analysis (e.g. CodeQL, Pysa) | Yes — tracks value through dict | High |
| LLM with full file context (vulnhuntr secondary loop) | Yes — semantic reasoning | Per-token |
| Manual review of known dispatch patterns | Yes | Human time |

### Implication for v2 pipeline

The current pipeline (semgrep → LLM) works well when semgrep can find the sink.
For dispatch-table RCE patterns, the right v2 approach is one of:

1. **Custom semgrep rule** targeting known-dangerous dicts by name
   (e.g., `EmbeddingModel[...]()` as a repo-specific rule). Scales poorly.

2. **AST dataflow pre-filter** (CodeQL or Pysa) as an alternative to semgrep
   for targets where dispatch-table patterns are common (ML/AI frameworks tend
   to have plugin registries everywhere).

3. **LLM-driven candidate generation** (ask LLM to read the route file and
   identify candidate sinks) as a fallback when semgrep produces 0 results.
   More expensive but catches semantic patterns.

**Short-term recommendation:** When `run_semgrep_intake.py` returns 0 candidates
on a target, flag it as a "semgrep-blind" target and route to LLM-driven candidate
generation rather than silently producing an empty audit.
