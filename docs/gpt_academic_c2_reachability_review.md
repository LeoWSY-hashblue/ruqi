# gpt_academic C2 Reachability Static Review

Target repository: `E:\tool\gpt_academic`

Target commit: `d6bde0fa54373309bd05823a49bda8da019d2c77`

Scope: Candidate C2, `crazy_functions/rag_fns/rag_file_support.py:6`,
`convert_to_markdown(file_path)`.

Dynamic verification: Not run.

LLM calls: Not run.

## Reviewed Functions/Files

- `crazy_functions/rag_fns/rag_file_support.py:1-29` - `convert_to_markdown`
- `crazy_functions/Document_Optimize.py:1-18`, `89-113`, `611-661` - import, `DocumentProcessor.process_file`, `自定义智能文档处理`
- `crazy_functions/paper_fns/reduce_aigc.py:1-18`, `147-170`, `787-855` - import, `DocumentProcessor.process_file`, `学术降重`
- `crazy_functional.py:641-710` - active/disabled plugin registration near dynamic function, Rag, and Document Optimize
- `shared_utils/fastapi_server.py:50-70` - `validate_path_safety`
- `shared_utils/connect_void_terminal.py:16-27` - generic plugin import helper
- `toolbox.py:93-149` - plugin dispatch and `lock_plugin` callback import
- `crazy_functions/vt_fns/vt_call_plugin.py:9-113` - Void Terminal plugin selection from `get_crazy_functions()`
- Whole-repository `convert_to_markdown(` call search

## Sink Finding

`convert_to_markdown(file_path)` constructs and executes an unquoted shell
command:

```python
md_path = os.path.splitext(file_path)[0] + '.md'
command = f"markitdown {file_path} > {md_path}"
subprocess.run(command, shell=True, check=True)
```

If an active route reaches this function with a user-controlled path containing
shell metacharacters, both `file_path` and derived `md_path` are potential shell
injection fields.

## Internal Call Chains

### Document_Optimize

`Document_Optimize.py` imports `convert_to_markdown` and calls it from
`DocumentProcessor.process_file(file_path)`.

The top-level plugin-like entry function `自定义智能文档处理(txt, ...)`:

1. checks `os.path.exists(txt)`;
2. calls `validate_path_safety(txt, user_name)`;
3. if `txt` is a file, sets `file_paths = [txt]`;
4. if `txt` is a directory, chooses an `.extract` child if present and glob-walks files;
5. filters supported extensions;
6. passes `file_paths[0]` into `processor.process_file(file_to_process)`;
7. `process_file` calls `convert_to_markdown(file_path)`.

### reduce_aigc

`paper_fns/reduce_aigc.py` imports `convert_to_markdown` and calls it from its
own `DocumentProcessor.process_file(file_path)`.

The top-level plugin-like entry function `学术降重(txt, ...)` has the same
relevant path shape:

1. checks `os.path.exists(txt)`;
2. calls `validate_path_safety(txt, user_name)`;
3. enumerates one file from either `txt` or an `.extract` directory under `txt`;
4. passes `file_to_process` into `processor.process_file(file_to_process)`;
5. `process_file` calls `convert_to_markdown(file_path)`.

## Active Registration Review

`crazy_functional.py` does not currently expose C2 through a normal active plugin
registration:

- `Document_Optimize` registration is present only as a commented-out block at
  `crazy_functional.py:691-708`.
- Whole-repository search found the `学术降重` function definition, but no active
  `crazy_functional.py` registration for it.
- Whole-repository search found only two relevant calls to
  `crazy_functions.rag_fns.rag_file_support.convert_to_markdown`: one in
  `Document_Optimize.py` and one in `paper_fns/reduce_aigc.py`.

## Other Route/API Review

Normal UI plugin dispatch is based on `get_crazy_functions()` and the
`function_plugins` dictionary. Since neither C2 entrypoint is active in that
dictionary, normal plugin selection does not prove reachability.

Void Terminal's plugin chooser also enumerates `get_crazy_functions()`, so it
does not independently expose the commented-out or unregistered C2 functions.

The repository contains generic dynamic mechanisms:

- `shared_utils/connect_void_terminal.py:get_plugin_handle(plugin_name)` can
  import `module->function` strings.
- `toolbox.py:ArgsGeneralWrapper` can dispatch `cookies['lock_plugin']` by
  importing `module->function`.
- `Dynamic_Function_Generate` is an active plugin that can generate code using an
  LLM and operate on recently uploaded files.

This review did not find a deterministic active UI/plugin/API route that passes
`crazy_functions.Document_Optimize->自定义智能文档处理` or
`crazy_functions.paper_fns.reduce_aigc->学术降重` into those generic mechanisms.
Those mechanisms remain residual context, not proof of current C2 reachability.

## User-Controlled Fields If Reachable

| Field | Static finding |
| --- | --- |
| `txt` | User-controlled plugin argument or uploaded-path value before entrypoint execution. |
| `file_path` | Derived from `txt` directly when `txt` is a file, or from glob results under `txt` / `.extract` when `txt` is a directory. |
| Archive member basename/path | Potentially user-controlled through upload extraction and glob enumeration. |
| `md_path` | Derived from `file_path` with extension replaced by `.md`; inherits path metacharacter risk from `file_path`. |

## Path Safety Finding

`validate_path_safety(txt, user_name)` is a boundary check, not a shell quoting or
path sanitization function. It checks that a path is under allowed roots such as
private upload or logging directories and under an allowed user prefix. It does
not quote `txt`, `file_path`, or `md_path` before shell command construction.

## Injection Surface If Reachable

| Command field | Source | Injection assessment |
| --- | --- | --- |
| `file_path` in `markitdown {file_path}` | `file_to_process` selected from uploaded file or extracted directory glob | Potentially injectable if an active route reaches C2 with a filename/path containing shell metacharacters. |
| `md_path` in `> {md_path}` | `os.path.splitext(file_path)[0] + '.md'` | Potentially injectable because it is derived from `file_path` and unquoted after shell redirection. |

## Exploitability Assessment

Assessment: `likely false positive / unreachable candidate`

Rationale:

- The sink is real and unsafe if called with user-controlled shell metacharacters.
- The internal `Document_Optimize` and `reduce_aigc` call chains can pass uploaded
  or extracted filenames to `convert_to_markdown`.
- However, no active normal UI/plugin registration was found for either
  `自定义智能文档处理` or `学术降重`.
- Void Terminal selection is based on active `get_crazy_functions()` entries and
  therefore does not prove reachability to the inactive C2 functions.
- Generic import/lock-plugin mechanisms exist, but this review did not find an
  active deterministic route that lets a normal user invoke the C2 functions
  through them.

## Recommended Next Step

Treat C2 as unreachable in the current registration state and do not run verifier
against it unless a concrete active route is found. If a route is later found,
the verifier PoC should target both unquoted fields in:

```text
markitdown {file_path} > {md_path}
```

using a controlled uploaded or extracted filename inside an isolated container.
