# Path Filter Audit

## Scope

- Script: `vulnhuntr/scripts/audit_path_filter.py`
- Project A: `vulnhuntr` itself, audited via a local tracked-files copy at `audit_targets/vulnhuntr-clean` so the nested external sample repo does not pollute the stats.
- Project B: `pallets-eco/flask-admin`
  - Reason for selection: Flask web codebase, 166 Python files / 26,617 Python lines, and it had not been analyzed earlier in this workspace.

## Statistics

| Project | Python files in repo (A) | Kept by `get_relevant_py_files()` (K) | Filtered out (F = A - K) | Suspicious filtered files |
| - | -: | -: | -: | -: |
| A: `vulnhuntr-clean` | 10 | 5 | 5 | 0 |
| B: `flask-admin` | 166 | 78 | 88 | 14 |

## Suspicious Filtered Files

### Project A: `vulnhuntr-clean`

No suspicious filtered files.

### Project B: `flask-admin`

All suspicious files were filtered because they live under `examples/` or `tests/` paths that match the current exclusion rules.

| Relative path | route decorator | request param | web import | sink keywords | filter reasons |
| - | - | - | - | - | - |
| `examples/auth/main.py` | yes | no | yes | `sqlalchemy` | `/example` |
| `examples/auth_flask_login/main.py` | yes | no | yes | `sqlalchemy` | `/example` |
| `examples/babel/main.py` | yes | no | yes | `sqlalchemy` | `/example` |
| `examples/bootstrap4/main.py` | yes | no | yes | `sqlalchemy` | `/example` |
| `examples/custom_layout/main.py` | yes | no | yes | `sqlalchemy` | `/example` |
| `examples/datetime_timezone/main.py` | yes | no | yes | `sqlalchemy` | `/example` |
| `examples/forms_files_images/main.py` | yes | no | yes | `sqlalchemy` | `/example` |
| `examples/geo_alchemy/main.py` | no | no | yes | `sqlalchemy` | `/example` |
| `examples/sqla_association_proxy/main.py` | yes | no | yes | `sqlalchemy` | `/example` |
| `examples/sqla_custom_inline_forms/main.py` | yes | no | yes | `sqlalchemy` | `/example` |
| `flask_admin/tests/conftest.py` | no | yes | yes | `sqlalchemy` | `/test`, `filename-pattern` |
| `flask_admin/tests/sqla/conftest.py` | no | yes | yes | `sqlalchemy` | `/test`, `filename-pattern` |
| `flask_admin/tests/sqla/test_basic.py` | no | yes | no | `sqlalchemy` | `/test`, `filename-pattern` |
| `flask_admin/tests/sqla/test_translation.py` | no | yes | no | `sqlalchemy` | `/test`, `filename-pattern` |

## Conclusion

`ISSUE-001` should still be fixed in W1.

The data from Project B does **not** show a flood of obviously wrong exclusions in normal source directories. The suspicious filtered files are all in `examples/` or `tests/`, which are reasonable places to exclude during primary code scanning.

But the implementation is still incorrect because the filter is based on substring matches against the **absolute path**. That makes behavior environment-dependent. We already observed this earlier when pytest temporary paths containing `/test` caused unrelated files to be excluded. A repository placed under a directory like `/testbed/`, `/testscratch/`, or any similar path segment can silently lose coverage.

So the problem is not "examples/tests are excluded". The problem is "the exclusion mechanism is path-fragile and can exclude non-test code depending on where the repo is stored." That is worth fixing before W1 broadens the candidate set with Semgrep, because silent under-collection will poison all later stages.

## Suggested W1 Fix

Replace absolute-path substring matching with repo-relative path-part matching. This keeps intentional exclusions while removing environment sensitivity.

```python
rel_parts = {part.lower() for part in f.relative_to(self.repo_path).parts}
if {'test', 'tests', 'example', 'examples', 'docs', 'dist', '.venv', 'virtualenv'} & rel_parts:
    continue
if f.name == 'setup.py' or f.name == 'conftest.py' or f.name.startswith('test_') or f.name.endswith('_test.py'):
    continue
```

This is the first W1 change I would make.


## Post-Fix Audit (W1)

After replacing the substring path filter with repo-relative directory-part matching, the audit results changed as follows.

| Project | Before kept | After kept | Before filtered | After filtered | Before suspicious filtered | After suspicious filtered |
| - | -: | -: | -: | -: | -: | -: |
| A: `vulnhuntr-clean` | 5 | 5 | 5 | 5 | 0 | 0 |
| B: `flask-admin` | 78 | 129 | 88 | 37 | 14 | 4 |

### `flask-admin` delta notes

- The suspicious filtered count dropped from `14` to `4`, which is the intended effect of bringing `examples/` into scope while still excluding `tests/`.
- The kept-file count increased by `51`, not `10`.
- Reason: `flask-admin/examples/` contains `52` Python files, and the new rule keeps all of them.
- One file moved in the opposite direction: `doc/conf.py` is now excluded because `doc/` is part of the explicit structured exclude set.
- Net change: `+52 examples` and `-1 doc/conf.py`, so `78 -> 129`.

### Remaining suspicious filtered files after the fix

| Relative path | route decorator | request param | web import | sink keywords | filter reasons |
| - | - | - | - | - | - |
| `flask_admin/tests/conftest.py` | no | yes | yes | `sqlalchemy` | `dir:tests`, `file:conftest.py` |
| `flask_admin/tests/sqla/conftest.py` | no | yes | yes | `sqlalchemy` | `dir:tests`, `file:conftest.py` |
| `flask_admin/tests/sqla/test_basic.py` | no | yes | no | `sqlalchemy` | `dir:tests`, `pattern:test_*.py` |
| `flask_admin/tests/sqla/test_translation.py` | no | yes | no | `sqlalchemy` | `dir:tests`, `pattern:test_*.py` |
