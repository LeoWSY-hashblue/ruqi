# W3 mlflow Semgrep Intake Triage

## Target

- Target repo: `https://github.com/mlflow/mlflow`
- Target path: `E:\tool\targets\mlflow`
- Target commit: `bd48f307152a9534dbe607c297fc5beae05cc1a5`
- Target status: clean
- LLM: Not run
- Verifier: Not run
- Confirmed findings: 0

## Semgrep Intake Summary

- Semgrep candidate count: 20
- Candidate type distribution:
  - RCE: 0
  - SSRF: 0
  - SQLi: 20
  - Path Traversal: 0

## Candidate Table

| Index | File | Line | Sink type | Rule | Enclosing symbol | Code snippet first 8 lines |
| ---: | --- | ---: | --- | --- | --- | --- |
| 1 | `mlflow/server/auth/db/migrations/versions/2ed73881770d_workspace_permissions.py` | 45 | `sqli` | `python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text` | `upgrade` | `batch_op.add_column(... server_default=sa.text(f"'{DEFAULT_WORKSPACE_NAME}'") ...)` |
| 2 | `mlflow/server/auth/sqlalchemy_store.py` | 237 | `sqli` | `python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text` | `SqlAlchemyStore.delete_user` | `for table in _RETAINED_LEGACY_PERMISSION_TABLES: session.execute(text(f"DELETE FROM {table} WHERE user_id = :uid"), {"uid": user.id})` |
| 3 | `mlflow/store/fs2db/__init__.py` | 34 | `sqli` | `python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text` | `_assert_empty_db` | `for table in ("experiments", "runs", "registered_models"): count = conn.execute(text(f"SELECT COUNT(*) FROM {table}")).scalar()` |
| 4 | `mlflow/store/model_registry/dbmodels/models.py` | 46 | `sqli` | `python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text` | `SqlRegisteredModel` | `workspace = Column(... server_default=sa.text(f"'{DEFAULT_WORKSPACE_NAME}'"))` |
| 5 | `mlflow/store/model_registry/dbmodels/models.py` | 104 | `sqli` | `python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text` | `SqlModelVersion` | `workspace = Column(... server_default=sa.text(f"'{DEFAULT_WORKSPACE_NAME}'"))` |
| 6 | `mlflow/store/model_registry/dbmodels/models.py` | 175 | `sqli` | `python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text` | `SqlRegisteredModelTag` | `workspace = Column(... server_default=sa.text(f"'{DEFAULT_WORKSPACE_NAME}'"))` |
| 7 | `mlflow/store/model_registry/dbmodels/models.py` | 213 | `sqli` | `python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text` | `SqlModelVersionTag` | `workspace = Column(... server_default=sa.text(f"'{DEFAULT_WORKSPACE_NAME}'")); name = Column(String(256), nullable=False)` |
| 8 | `mlflow/store/model_registry/dbmodels/models.py` | 256 | `sqli` | `python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text` | `SqlRegisteredModelAlias` | `workspace = Column(... server_default=sa.text(f"'{DEFAULT_WORKSPACE_NAME}'"))` |
| 9 | `mlflow/store/model_registry/dbmodels/models.py` | 321 | `sqli` | `python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text` | `SqlWebhook` | `workspace = Column(... server_default=sa.text(f"'{DEFAULT_WORKSPACE_NAME}'")); webhook_id = Column(String(256), nullable=False)` |
| 10 | `mlflow/store/tracking/dbmodels/models.py` | 138 | `sqli` | `python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text` | `SqlExperiment` | `workspace = Column(... server_default=sa.text(f"'{DEFAULT_WORKSPACE_NAME}'"))` |
| 11 | `mlflow/store/tracking/dbmodels/models.py` | 1571 | `sqli` | `python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text` | `SqlEvaluationDataset` | `workspace = Column(... server_default=sa.text(f"'{DEFAULT_WORKSPACE_NAME}'"))` |
| 12 | `mlflow/store/tracking/dbmodels/models.py` | 2322 | `sqli` | `python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text` | `SqlJob` | `workspace = Column(... server_default=sa.text(f"'{DEFAULT_WORKSPACE_NAME}'"))` |
| 13 | `mlflow/store/tracking/dbmodels/models.py` | 2484 | `sqli` | `python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text` | `SqlGatewaySecret` | `workspace = Column(... server_default=sa.text(f"'{DEFAULT_WORKSPACE_NAME}'"))` |
| 14 | `mlflow/store/tracking/dbmodels/models.py` | 2578 | `sqli` | `python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text` | `SqlGatewayEndpoint` | `workspace = Column(... server_default=sa.text(f"'{DEFAULT_WORKSPACE_NAME}'"))` |
| 15 | `mlflow/store/tracking/dbmodels/models.py` | 2684 | `sqli` | `python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text` | `SqlGatewayModelDefinition` | `workspace = Column(... server_default=sa.text(f"'{DEFAULT_WORKSPACE_NAME}'"))` |
| 16 | `mlflow/store/tracking/dbmodels/models.py` | 3000 | `sqli` | `python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text` | `SqlGatewayBudgetPolicy` | `workspace = Column(... server_default=sa.text(f"'{DEFAULT_WORKSPACE_NAME}'"))` |
| 17 | `mlflow/store/tracking/dbmodels/models.py` | 3101 | `sqli` | `python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text` | `SqlGatewayGuardrail` | `workspace = Column(... server_default=sa.text(f"'{DEFAULT_WORKSPACE_NAME}'"))` |
| 18 | `mlflow/store/tracking/dbmodels/models.py` | 3190 | `sqli` | `python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text` | `SqlGatewayGuardrailConfig` | `workspace = Column(... server_default=sa.text(f"'{DEFAULT_WORKSPACE_NAME}'"))` |
| 19 | `mlflow/utils/search_utils.py` | 302 | `sqli` | `python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text` | `SearchUtils.get_sql_comparison_func.mysql_comparison_func` | `column = f"{column.class_.__tablename__}.{column.key}"; return sa.text(templates[comparator].format(column=column)).bindparams(...)` |
| 20 | `mlflow/utils/search_utils.py` | 2021 | `sqli` | `python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text` | `SearchTraceUtils._get_sql_json_comparison_func.mysql_json_equality_inequality_comparison` | `template = f"(({col_ref} = :value1 AND BINARY {col_ref} = :value1) OR ..."; return sa.text(template).bindparams(...)` |

## Initial Triage Checklist

### Candidate 1

- active entrypoint?: TBD
- user-controlled field?: TBD
- sink argument preserves taint?: TBD
- sanitizer/path rewrite?: TBD
- verifier feasible?: TBD

### Candidate 2

- active entrypoint?: TBD
- user-controlled field?: TBD
- sink argument preserves taint?: TBD
- sanitizer/path rewrite?: TBD
- verifier feasible?: TBD

### Candidate 3

- active entrypoint?: TBD
- user-controlled field?: TBD
- sink argument preserves taint?: TBD
- sanitizer/path rewrite?: TBD
- verifier feasible?: TBD

### Candidate 4

- active entrypoint?: TBD
- user-controlled field?: TBD
- sink argument preserves taint?: TBD
- sanitizer/path rewrite?: TBD
- verifier feasible?: TBD

### Candidate 5

- active entrypoint?: TBD
- user-controlled field?: TBD
- sink argument preserves taint?: TBD
- sanitizer/path rewrite?: TBD
- verifier feasible?: TBD

### Candidate 6

- active entrypoint?: TBD
- user-controlled field?: TBD
- sink argument preserves taint?: TBD
- sanitizer/path rewrite?: TBD
- verifier feasible?: TBD

### Candidate 7

- active entrypoint?: TBD
- user-controlled field?: TBD
- sink argument preserves taint?: TBD
- sanitizer/path rewrite?: TBD
- verifier feasible?: TBD

### Candidate 8

- active entrypoint?: TBD
- user-controlled field?: TBD
- sink argument preserves taint?: TBD
- sanitizer/path rewrite?: TBD
- verifier feasible?: TBD

### Candidate 9

- active entrypoint?: TBD
- user-controlled field?: TBD
- sink argument preserves taint?: TBD
- sanitizer/path rewrite?: TBD
- verifier feasible?: TBD

### Candidate 10

- active entrypoint?: TBD
- user-controlled field?: TBD
- sink argument preserves taint?: TBD
- sanitizer/path rewrite?: TBD
- verifier feasible?: TBD

### Candidate 11

- active entrypoint?: TBD
- user-controlled field?: TBD
- sink argument preserves taint?: TBD
- sanitizer/path rewrite?: TBD
- verifier feasible?: TBD

### Candidate 12

- active entrypoint?: TBD
- user-controlled field?: TBD
- sink argument preserves taint?: TBD
- sanitizer/path rewrite?: TBD
- verifier feasible?: TBD

### Candidate 13

- active entrypoint?: TBD
- user-controlled field?: TBD
- sink argument preserves taint?: TBD
- sanitizer/path rewrite?: TBD
- verifier feasible?: TBD

### Candidate 14

- active entrypoint?: TBD
- user-controlled field?: TBD
- sink argument preserves taint?: TBD
- sanitizer/path rewrite?: TBD
- verifier feasible?: TBD

### Candidate 15

- active entrypoint?: TBD
- user-controlled field?: TBD
- sink argument preserves taint?: TBD
- sanitizer/path rewrite?: TBD
- verifier feasible?: TBD

### Candidate 16

- active entrypoint?: TBD
- user-controlled field?: TBD
- sink argument preserves taint?: TBD
- sanitizer/path rewrite?: TBD
- verifier feasible?: TBD

### Candidate 17

- active entrypoint?: TBD
- user-controlled field?: TBD
- sink argument preserves taint?: TBD
- sanitizer/path rewrite?: TBD
- verifier feasible?: TBD

### Candidate 18

- active entrypoint?: TBD
- user-controlled field?: TBD
- sink argument preserves taint?: TBD
- sanitizer/path rewrite?: TBD
- verifier feasible?: TBD

### Candidate 19

- active entrypoint?: TBD
- user-controlled field?: TBD
- sink argument preserves taint?: TBD
- sanitizer/path rewrite?: TBD
- verifier feasible?: TBD

### Candidate 20

- active entrypoint?: TBD
- user-controlled field?: TBD
- sink argument preserves taint?: TBD
- sanitizer/path rewrite?: TBD
- verifier feasible?: TBD

## Notes

- This is an intake-only draft.
- Most candidates are SQLAlchemy `sa.text(...)` usage in migrations, ORM model defaults, or internal query helpers.
- LLM-assisted call-chain reconstruction was not run.
- Dynamic verifier was not run.
- Confirmed findings remain 0.

## SQLi Cluster Triage

Clusters are grouped by `file + enclosing_symbol`. This produces 20 clusters from
20 Semgrep candidates.

| Cluster id | File | Enclosing symbol | Candidate count | Active entrypoint assessment | Taint assessment | Sanitizer/binding assessment | Priority | Rationale |
| --- | --- | --- | ---: | --- | --- | --- | --- | --- |
| C01 | `mlflow/server/auth/db/migrations/versions/2ed73881770d_workspace_permissions.py` | `upgrade` | 1 | Migration path, not active REST/API. | No user-controlled SQL fragment observed. | `DEFAULT_WORKSPACE_NAME` constant in `sa.text(...)`. | Drop | Alembic migration metadata/default, not runtime request handling. |
| C02 | `mlflow/server/auth/sqlalchemy_store.py` | `SqlAlchemyStore.delete_user` | 1 | Internal auth store method, plausibly reachable only through admin/user-management service paths. | `username` selects a user, but SQL table fragment comes from `_RETAINED_LEGACY_PERMISSION_TABLES` constant tuple. | `user.id` is bound as `:uid`; table names are fixed constants. | P2 | Active/internal path possible, but no user input reaches the raw SQL fragment. |
| C03 | `mlflow/store/fs2db/__init__.py` | `_assert_empty_db` | 1 | CLI/migration utility path, not active REST/API. | Table names are fixed tuple literals. | No user-controlled SQL fragment; static table list. | Drop | Offline fs2db migration helper. |
| C04 | `mlflow/store/model_registry/dbmodels/models.py` | `SqlRegisteredModel` | 1 | ORM model metadata, not request handler. | No request-derived SQL fragment. | `server_default=sa.text(...)` uses `DEFAULT_WORKSPACE_NAME` constant. | P2 | Model default declaration; no dynamic taint. |
| C05 | `mlflow/store/model_registry/dbmodels/models.py` | `SqlModelVersion` | 1 | ORM model metadata, not request handler. | No request-derived SQL fragment. | `server_default=sa.text(...)` uses `DEFAULT_WORKSPACE_NAME` constant. | P2 | Model default declaration; no dynamic taint. |
| C06 | `mlflow/store/model_registry/dbmodels/models.py` | `SqlRegisteredModelTag` | 1 | ORM model metadata, not request handler. | No request-derived SQL fragment. | `server_default=sa.text(...)` uses `DEFAULT_WORKSPACE_NAME` constant. | P2 | Model default declaration; no dynamic taint. |
| C07 | `mlflow/store/model_registry/dbmodels/models.py` | `SqlModelVersionTag` | 1 | ORM model metadata, not request handler. | No request-derived SQL fragment. | `server_default=sa.text(...)` uses `DEFAULT_WORKSPACE_NAME` constant. | P2 | Model default declaration; no dynamic taint. |
| C08 | `mlflow/store/model_registry/dbmodels/models.py` | `SqlRegisteredModelAlias` | 1 | ORM model metadata, not request handler. | No request-derived SQL fragment. | `server_default=sa.text(...)` uses `DEFAULT_WORKSPACE_NAME` constant. | P2 | Model default declaration; no dynamic taint. |
| C09 | `mlflow/store/model_registry/dbmodels/models.py` | `SqlWebhook` | 1 | ORM model metadata, not request handler. | No request-derived SQL fragment. | `server_default=sa.text(...)` uses `DEFAULT_WORKSPACE_NAME` constant. | P2 | Model default declaration; no dynamic taint despite webhook entity being runtime-relevant. |
| C10 | `mlflow/store/tracking/dbmodels/models.py` | `SqlExperiment` | 1 | ORM model metadata, not request handler. | No request-derived SQL fragment. | `server_default=sa.text(...)` uses `DEFAULT_WORKSPACE_NAME` constant. | P2 | Model default declaration; no dynamic taint. |
| C11 | `mlflow/store/tracking/dbmodels/models.py` | `SqlEvaluationDataset` | 1 | ORM model metadata, not request handler. | No request-derived SQL fragment. | `server_default=sa.text(...)` uses `DEFAULT_WORKSPACE_NAME` constant. | P2 | Model default declaration; no dynamic taint. |
| C12 | `mlflow/store/tracking/dbmodels/models.py` | `SqlJob` | 1 | ORM model metadata, not request handler. | No request-derived SQL fragment. | `server_default=sa.text(...)` uses `DEFAULT_WORKSPACE_NAME` constant. | P2 | Model default declaration; no dynamic taint. |
| C13 | `mlflow/store/tracking/dbmodels/models.py` | `SqlGatewaySecret` | 1 | ORM model metadata, not request handler. | No request-derived SQL fragment. | `server_default=sa.text(...)` uses `DEFAULT_WORKSPACE_NAME` constant. | P2 | Model default declaration; no dynamic taint. |
| C14 | `mlflow/store/tracking/dbmodels/models.py` | `SqlGatewayEndpoint` | 1 | ORM model metadata, not request handler. | No request-derived SQL fragment. | `server_default=sa.text(...)` uses `DEFAULT_WORKSPACE_NAME` constant. | P2 | Model default declaration; no dynamic taint. |
| C15 | `mlflow/store/tracking/dbmodels/models.py` | `SqlGatewayModelDefinition` | 1 | ORM model metadata, not request handler. | No request-derived SQL fragment. | `server_default=sa.text(...)` uses `DEFAULT_WORKSPACE_NAME` constant. | P2 | Model default declaration; no dynamic taint. |
| C16 | `mlflow/store/tracking/dbmodels/models.py` | `SqlGatewayBudgetPolicy` | 1 | ORM model metadata, not request handler. | No request-derived SQL fragment. | `server_default=sa.text(...)` uses `DEFAULT_WORKSPACE_NAME` constant. | P2 | Model default declaration; no dynamic taint. |
| C17 | `mlflow/store/tracking/dbmodels/models.py` | `SqlGatewayGuardrail` | 1 | ORM model metadata, not request handler. | No request-derived SQL fragment. | `server_default=sa.text(...)` uses `DEFAULT_WORKSPACE_NAME` constant. | P2 | Model default declaration; no dynamic taint. |
| C18 | `mlflow/store/tracking/dbmodels/models.py` | `SqlGatewayGuardrailConfig` | 1 | ORM model metadata, not request handler. | No request-derived SQL fragment. | `server_default=sa.text(...)` uses `DEFAULT_WORKSPACE_NAME` constant. | P2 | Model default declaration; no dynamic taint. |
| C19 | `mlflow/utils/search_utils.py` | `SearchUtils.get_sql_comparison_func.mysql_comparison_func` | 1 | Likely active through search/filter APIs. | User controls search filter value/comparator, but column is derived from parsed/validated search identifiers and SQLAlchemy column metadata. | Values are bound with `sa.bindparam`; column fragment comes from `column.class_.__tablename__` and `column.key`. | P2 | Runtime path likely exists, but raw SQL text uses fixed templates and bound values. |
| C20 | `mlflow/utils/search_utils.py` | `SearchTraceUtils._get_sql_json_comparison_func.mysql_json_equality_inequality_comparison` | 1 | Likely active through trace search/filter APIs. | User controls search filter value/comparator, but column reference comes from SQLAlchemy column metadata after parser validation. | Values are bound with `sa.bindparam`; comparator restricted to `=`/`!=` for this helper. | P2 | Runtime path likely exists, but raw SQL text uses fixed templates and bound values. |

## Next Triage Targets

- No SQLi cluster currently qualifies for LLM or verifier.
- Best manual follow-up, if required: C19 and C20 search utility clusters, because they are closest to active API search paths.
- C19/C20 current priority remains P2 due to parser validation, SQLAlchemy column-derived identifiers, fixed SQL templates, and bound user values.
