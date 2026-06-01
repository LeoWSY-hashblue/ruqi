# gpt_academic C1 Path-Control Static Review

Target repository: `E:\tool\gpt_academic`

Target commit: `d6bde0fa54373309bd05823a49bda8da019d2c77`

Scope: Candidate C1, `crazy_functions/latex_fns/latex_toolbox.py:595`,
`compile_latex_with_timeout(command, shell=True)`.

Dynamic verification: Not run.

LLM calls: Not run.

## Reviewed Functions/Files

- `shared_utils/fastapi_server.py:50-70` - `validate_path_safety`
- `shared_utils/handle_upload.py:45-88` - `zip_extract_member_new`
- `shared_utils/handle_upload.py:92-114` - `safe_extract_rar`
- `shared_utils/handle_upload.py:117-180` - `extract_archive`
- `toolbox.py:511-574` - `on_file_uploaded`
- `crazy_functions/Latex_Function.py:44-89` - `descend_to_extracted_folder_if_exist`, `move_project`
- `crazy_functions/Latex_Function.py:91-178` - `arxiv_download`
- `crazy_functions/Latex_Function.py:286-309`, `406-425`, `553-579` - all observed `编译Latex(` call sites
- `crazy_functions/latex_fns/latex_actions.py:347-428` - `编译Latex`, `get_compile_command`, and all `compile_latex_with_timeout` command construction
- `crazy_functions/latex_fns/latex_toolbox.py:595-608` - `compile_latex_with_timeout`

## Data-Flow Finding

The active LaTeX plugin paths can reach `compile_latex_with_timeout(command, shell=True)`.
However, the observed shell command strings do not currently contain user-controlled
upload filenames, extracted archive member names, or uploaded directory names.

For normal uploaded LaTeX projects:

1. `on_file_uploaded` stores each uploaded file as
   `target_path_base / os.path.basename(file.orig_name)` and then sets `txt` to
   `target_path_base`.
2. `descend_to_extracted_folder_if_exist` may switch `project_folder` to a
   direct child ending in `.extract`.
3. `validate_path_safety` only checks that the path is under an allowed root and
   user prefix. It does not shell-escape path components.
4. `move_project(project_folder, arxiv_id=None)` copies the selected project
   into `get_log_folder()/gen_time_str()` and returns that generated destination.
5. All observed `编译Latex(` calls pass fixed `main_file_original` and
   `main_file_modified` values.
6. `compile_latex_with_timeout` receives unquoted shell strings, but the
   interpolated filename fields are fixed logical names and the work folder is a
   generated path for local uploads.

For Arxiv input:

1. `arxiv_download` derives `arxiv_id` from `https://arxiv.org/abs/...` without a
   strict regex validation step.
2. `move_project(project_folder, arxiv_id)` uses
   `ARXIV_CACHE_DIR / arxiv_id / workfolder`.
3. The observed Arxiv translation call passes `mode='translate_zh'`, so the
   `latexdiff` command block is skipped.
4. The remaining `pdflatex`, `xelatex`, and `bibtex` command strings use fixed
   filenames and pass the working directory as `cwd`, not as part of the shell
   command string.

## User-Controlled Fields

| Field | Static finding |
| --- | --- |
| Uploaded original basename | Preserved with `os.path.basename(file.orig_name)`. Shell metacharacters are not explicitly removed by this code, subject to client/OS filename constraints. |
| Archive member names | Zip/tar/rar extraction blocks traversal and symlinks in several cases, but does not generally strip shell metacharacters from safe relative names. |
| Top-level extracted wrapper directory | Can influence which source directory `move_project` copies when the project has a single wrapper directory and no top-level `.tex`. |
| `txt` / `txt2` | User-controlled before plugin dispatch; upload callback sets `txt` to generated `target_path_base`. |
| Arxiv URL suffix / `arxiv_id` | Partially user-derived for `https://arxiv.org/abs/...`; static review did not find strict validation beyond URL prefix and version truncation. |

## Not-Proven-Controlled Fields

| Field | Static finding |
| --- | --- |
| `main_file_original` | All observed call sites pass fixed values: `merge`. |
| `main_file_modified` | All observed call sites pass fixed values: `merge_proofread_en` or `merge_translate_zh`. |
| `compiler` | Set internally to `pdflatex` or `xelatex` based on package detection and binary availability. |
| Local-upload `work_folder*` | Rewritten by `move_project(..., arxiv_id=None)` to `get_log_folder()/gen_time_str()`. |
| Arxiv `work_folder*` in `latexdiff` | Would include `arxiv_id`, but the observed Arxiv translation call uses `mode='translate_zh'`, which skips `latexdiff`. |

## Shell Command Construction Table

| Location | Command | Interpolated fields | User control assessment |
| --- | --- | --- | --- |
| `latex_actions.py:374-377` | `<compiler> -interaction=batchmode -file-line-error <filename>.tex` | `compiler`, `filename` | `compiler` is internal; observed `filename` values are fixed. |
| `latex_actions.py:400,403,414-417,425,427-428` | `get_compile_command(...)` | Same as above | No proven user-controlled shell metacharacters. |
| `latex_actions.py:409,411` | `bibtex <main_file>.aux` | `main_file_original`, `main_file_modified` | Observed values are fixed. |
| `latex_actions.py:422` | `latexdiff ... {work_folder_original}/{main_file_original}.tex ... > {work_folder}/merge_diff.tex` | `work_folder*`, `main_file*` | Most plausible injection surface because path fields are unquoted, but observed local-upload paths are generated and observed Arxiv path skips this block. |
| `latex_actions.py:426` | `bibtex merge_diff.aux` | None | Fixed string. |

## Exploitability Assessment

Assessment: `likely false positive`

Rationale:

- The sink is real: `subprocess.Popen(command, shell=True)` executes shell
  strings.
- The active LaTeX plugin chain can reach the sink.
- Static review did not find a route where uploaded filenames, archive member
  names, or uploaded directory names survive into the shell command string.
- `move_project` copies local uploads into a generated log directory, removing
  user-controlled source path components from `work_folder*`.
- All observed `main_file_original` and `main_file_modified` arguments are fixed
  logical names.
- `compiler` is selected internally from a fixed pair.
- The unquoted `latexdiff` command remains the most suspicious construction, but
  its path fields are not proven user-controlled in the observed active flows.

Residual uncertainty:

- `arxiv_id` is weakly validated and may influence cache paths, but the observed
  Arxiv flow uses `mode='translate_zh'`, which skips `latexdiff`.
- This review did not execute the app, Docker, LaTeX tooling, or verifier.
- A future or unobserved call site that passes user-controlled `main_file*` or
  uses Arxiv-derived `work_folder*` with non-`translate_zh` mode would change the
  assessment.

## Recommended Next Step

Do not proceed to a dynamic verifier PoC for C1 until a concrete field-to-command
path is found. The next static step should be:

1. Confirm there are no dynamic imports or plugin wrappers that call `编译Latex`
   with user-controlled `main_file_original`, `main_file_modified`, or
   non-generated `work_folder*`.
2. Review `arxiv_id` handling separately as a path validation issue, especially
   cache behavior, but treat it as distinct from the observed C1 shell command
   injection hypothesis.
3. If no additional call site is found, mark C1 as a Semgrep `shell=True`
   false positive in the first report rather than attempting verifier execution.
