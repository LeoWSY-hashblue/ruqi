# Semgrep Intake — First Run Report

**Target:** `audit_targets/flask-admin`
**Config:** `p/python` (switched from `p/security-audit`; see rationale below)
**Date:** 2026-05-31
**Semgrep version:** 1.163.0

---

## Summary

| Metric | Value |
| - | - |
| Total semgrep results (`p/python`) | 22 |
| Python-file results | 22 |
| Candidates produced by `run_semgrep()` | **1** |
| Mapping-table coverage | **4.5%** |

---

## Sink-type distribution

| sink_type | count |
| - | -: |
| `sqli` | 1 |
| `rce` | 0 |
| `ssrf` | 0 |
| `path_traversal` | 0 |

---

## Rule-id distribution (top 10, all Python results)

| count | rule_id | mapped_to |
| -: | - | - |
| 21 | `python.flask.security.audit.debug-enabled.debug-enabled` | UNMAPPED |
| 1 | `python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text` | `sqli` |

Only 2 distinct rules fired on Python files. `debug-enabled` (21 hits) detects
`app.run(debug=True)` in `examples/*/main.py`; it is a dev-config issue, not a
server-side sink, and is intentionally left unmapped.

---

## Mapping-table coverage

**4.5%** of Python-file results map to a known sink type (1 of 22).

The 21 unmapped hits are all `debug-enabled`; adding them to the mapping table would
not be useful. As we add more target repos (especially those that use subprocess,
eval, or raw SQL), coverage will rise naturally.

---

## Candidate sample (complete `run_semgrep_intake.py` output)

```json
[
  {
    "file": "flask_admin/contrib/sqla/ajax.py",
    "line": 112,
    "sink_type": "sqli",
    "semgrep_rule_id": "python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text",
    "code_snippet": "        )\n        query = query.filter(or_(*filters))\n\n        if self.filters:\n            filters = [\n                text(f\"{self.model.__tablename__.lower()}.{value}\")\n                for value in self.filters\n            ]\n            query = query.filter(and_(*filters))\n\n        if self.order_by:",
    "enclosing_symbol": "QueryAjaxModelLoader.get_list",
    "enclosing_source": "def get_list(\n        self, term: str, offset: int = 0, limit: int = DEFAULT_PAGE_SIZE\n    ) -> t.Any:\n        query = self.get_query()\n\n        # no type casting to string if a ColumnAssociationProxyInstance is given\n        filters: t.Any = (\n            field.ilike(f\"%{term}%\")\n            if is_association_proxy(field)\n            else cast(field, String).ilike(f\"%{term}%\")\n            for field in self._cached_fields\n        )\n        query = query.filter(or_(*filters))\n\n        if self.filters:\n            filters = [\n                text(f\"{self.model.__tablename__.lower()}.{value}\")\n                for value in self.filters\n            ]\n            query = query.filter(and_(*filters))\n\n        if self.order_by:\n            query = query.order_by(self.order_by)\n\n        return query.offset(offset).limit(limit).all()"
  }
]
```

### Candidate analysis

`QueryAjaxModelLoader.get_list` builds a raw SQLAlchemy `text()` fragment with an
f-string at `flask_admin/contrib/sqla/ajax.py:112`:

```python
text(f"{self.model.__tablename__.lower()}.{value}")
```

**Data flow:**
- `self.model.__tablename__` — from the ORM model class definition; not HTTP input.
- `value` — iterates over `self.filters`, which is set from `options["filters"]` at
  admin class construction time (developer-configured, not from an HTTP request body).
- `term` (the actual user-supplied AJAX search string, line 97) is used safely via
  SQLAlchemy's `.ilike()` parameterized binding — no injection there.

**Assessment:** `self.filters` is developer-configured, not user-supplied at request
time. The injection surface is indirect: if an attacker can influence the admin class
configuration (e.g., via a separate config-injection bug), `value` could become
attacker-controlled. As a standalone finding, confidence is low (≤ 5). The LLM
secondary-analysis pass should trace whether any HTTP-facing code path allows
`self.filters` to include externally-supplied data before escalating.

---

## Config-switch rationale

The original `_run_semgrep_command` used `--config=p/security-audit`. A comparison
run on flask-admin showed:

| Config | Total results | Python results | Candidates |
| - | -: | -: | -: |
| `p/security-audit` | 138 | 38 | 0 |
| `p/python` | 22 | 22 | **1** |

With `p/security-audit`, Python rules that fired were only `debug-enabled` and
`hardcoded-config` (both config issues, not sinks). The SQLAlchemy `text()` rule that
produced our only Candidate is in `p/python` but **not** in `p/security-audit`.

`p/security-audit` is a cross-language pack; for Python-only repos `p/python` is both
more focused and more likely to surface patterns relevant to our 4 target sink types.
`_run_semgrep_command` has been updated accordingly.

---

## Mapping-table additions made in this run

`SEMGREP_RULE_TO_SINK` was extended after this first run per the "expand after real
data" protocol:

```python
# Added after flask-admin first run
'python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text': 'sqli',
```

Current full table:

| rule_id | sink_type |
| - | - |
| `python.lang.security.audit.eval-detected.eval-detected` | `rce` |
| `python.lang.security.audit.exec-detected.exec-detected` | `rce` |
| `python.lang.security.audit.subprocess-shell-true.subprocess-shell-true` | `rce` |
| `python.lang.security.audit.formatted-sql-query.formatted-sql-query` | `sqli` |
| `python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text` | `sqli` |
| `python.requests.security.disabled-cert-validation.disabled-cert-validation` | `ssrf` |

---

## Known follow-up

1. **No `path_traversal` rules yet.** Flask-admin handles file uploads via
   `FileAdmin`. Adding path-traversal rules (e.g.,
   `python.lang.security.audit.open-redirect.*` or file-write patterns) should
   surface candidates in the file-management code paths.

2. **Coverage is expected to be low on this target.** Flask-admin uses SQLAlchemy ORM
   throughout and avoids `eval`/`exec`/subprocess directly. As we add repos with
   different architectures (raw SQL, subprocess wrappers, outbound HTTP), coverage will
   grow.

3. **The single Candidate warrants LLM deep-dive.** Trace whether any HTTP-facing view
   in flask-admin passes user-controlled data into the `filters` option of
   `QueryAjaxModelLoader`. If yes, this becomes a genuine SQLi candidate.
