# Known Issues

- ISSUE-001: `/test` path filtering is too broad in `RepoOps.get_relevant_py_files()` and can exclude legitimate repositories or fixtures whose absolute path happens to contain that substring. Closed in W1 by switching to repo-relative path-part matching with explicit exclude rules.
- ISSUE-002: The secondary analysis loop has no explicit hard cap for token budget, wall-clock time, or a separately modeled round budget beyond the current duplicate-context break path. Closed in W1: added MAX_SECONDARY_ROUNDS=10, MAX_CONTEXT_TOKENS_PER_FILE=40000, MAX_WALL_SECONDS_PER_FILE=180 guards in _run_secondary_loop(); abort_reason field added to Response.
- ISSUE-003: The tool does not estimate or track API cost before and during analysis, so there is no cost-control surface for users or batch orchestration. Deferred to W2.
