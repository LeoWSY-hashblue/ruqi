# gpt_academic RCE Call Chain Context

## Target commit

- Target repository: `E:\tool\gpt_academic`
- Commit: `d6bde0fa54373309bd05823a49bda8da019d2c77`
- Scope: offline static context only. No LLM call, verifier run, Docker run, or target source modification has been performed.

## Candidate summary

| Candidate | File | Line | Sink | Rule | Symbol |
| --- | --- | ---: | --- | --- | --- |
| C1 | `crazy_functions/latex_fns/latex_toolbox.py` | 599 | `subprocess.Popen(..., shell=True)` | `python.lang.security.audit.subprocess-shell-true.subprocess-shell-true` | `compile_latex_with_timeout` |
| C2 | `crazy_functions/rag_fns/rag_file_support.py` | 22 | `subprocess.run(..., shell=True)` | `python.lang.security.audit.subprocess-shell-true.subprocess-shell-true` | `convert_to_markdown` |

## Candidate 1 static context

### Sink function

Location: `crazy_functions/latex_fns/latex_toolbox.py:595-608`

```python
def compile_latex_with_timeout(command, cwd, timeout=60):
    import subprocess

    process = subprocess.Popen(
        command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=cwd
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        stdout, stderr = process.communicate()
        logger.error("Process timed out (compile_latex_with_timeout)!")
        return False
    return True
```

### Direct call sites found by `rg`

- `crazy_functions/latex_fns/latex_actions.py:400`: `compile_latex_with_timeout(get_compile_command(compiler, main_file_original), work_folder_original)`
- `crazy_functions/latex_fns/latex_actions.py:403`: `compile_latex_with_timeout(get_compile_command(compiler, main_file_modified), work_folder_modified)`
- `crazy_functions/latex_fns/latex_actions.py:409`: `compile_latex_with_timeout(f'bibtex  {main_file_original}.aux', work_folder_original)`
- `crazy_functions/latex_fns/latex_actions.py:411`: `compile_latex_with_timeout(f'bibtex  {main_file_modified}.aux', work_folder_modified)`
- `crazy_functions/latex_fns/latex_actions.py:414-417`: repeated compile commands for original/modified files
- `crazy_functions/latex_fns/latex_actions.py:422`: `compile_latex_with_timeout(f'latexdiff ... {work_folder_original}/{main_file_original}.tex ... {work_folder_modified}/{main_file_modified}.tex ... > {work_folder}/merge_diff.tex', os.getcwd())`
- `crazy_functions/latex_fns/latex_actions.py:425-428`: compile and bibtex commands for `merge_diff`

### Calling function

Location: `crazy_functions/latex_fns/latex_actions.py:347-428`

```python
def 编译Latex(chatbot, history, main_file_original, main_file_modified, work_folder_original, work_folder_modified, work_folder, mode='default'):
    import os, time
    n_fix = 1
    max_try = 32

    def get_compile_command(compiler, filename):
        compile_command = f'{compiler} -interaction=batchmode -file-line-error {filename}.tex'
        logger.info('Latex 编译指令: ' + compile_command)
        return compile_command

    compiler = 'pdflatex'
    if check_if_need_xelatex(pj(work_folder_modified, f'{main_file_modified}.tex')):
        subprocess.run(['xelatex', '--version'], capture_output=True, check=True)
        compiler = 'xelatex'

    while True:
        ok = compile_latex_with_timeout(get_compile_command(compiler, main_file_original), work_folder_original)
        ok = compile_latex_with_timeout(get_compile_command(compiler, main_file_modified), work_folder_modified)
        if ok and os.path.exists(pj(work_folder_modified, f'{main_file_modified}.pdf')):
            if not os.path.exists(pj(work_folder_original, f'{main_file_original}.bbl')):
                ok = compile_latex_with_timeout(f'bibtex  {main_file_original}.aux', work_folder_original)
            if not os.path.exists(pj(work_folder_modified, f'{main_file_modified}.bbl')):
                ok = compile_latex_with_timeout(f'bibtex  {main_file_modified}.aux', work_folder_modified)
            ok = compile_latex_with_timeout(get_compile_command(compiler, main_file_original), work_folder_original)
            ok = compile_latex_with_timeout(get_compile_command(compiler, main_file_modified), work_folder_modified)
            if mode != 'translate_zh':
                ok = compile_latex_with_timeout(
                    f'latexdiff --encoding=utf8 --append-safecmd=subfile {work_folder_original}/{main_file_original}.tex  {work_folder_modified}/{main_file_modified}.tex --flatten > {work_folder}/merge_diff.tex',
                    os.getcwd(),
                )
                ok = compile_latex_with_timeout(get_compile_command(compiler, 'merge_diff'), work_folder)
                ok = compile_latex_with_timeout(f'bibtex    merge_diff.aux', work_folder)
```

### Upstream callers and likely entrypoints

`编译Latex` is called by LaTeX plugins in `crazy_functions/Latex_Function.py`:

- `Latex英文纠错加PDF对比(...)` at lines `253-322`
- `Latex翻译中文并重新编译PDF(...)` at lines `331-437`
- `PDF翻译中文并重新编译PDF(...)` at lines `454-585`

Relevant path and file input flow:

```python
def Latex翻译中文并重新编译PDF(txt, llm_kwargs, plugin_kwargs, chatbot, history, system_prompt, user_request):
    txt, arxiv_id = yield from arxiv_download(chatbot, history, txt, allow_cache)
    if os.path.exists(txt):
        project_folder = txt
    file_manifest = [f for f in glob.glob(f'{project_folder}/**/*.tex', recursive=True)]
    project_folder = descend_to_extracted_folder_if_exist(project_folder)
    validate_path_safety(project_folder, chatbot.get_user())
    project_folder = move_project(project_folder, arxiv_id)
    yield from Latex精细分解与转化(...)
    success = yield from 编译Latex(..., main_file_original='merge', main_file_modified='merge_translate_zh', ...)
```

```python
def PDF翻译中文并重新编译PDF(txt, llm_kwargs, plugin_kwargs, chatbot, history, system_prompt, web_port):
    if os.path.exists(txt):
        project_folder = txt
    file_manifest = [f for f in glob.glob(f'{project_folder}/**/*.pdf', recursive=True)]
    project_folder = pdf2tex_project(file_manifest[0], plugin_kwargs)
    validate_path_safety(project_folder, chatbot.get_user())
    project_folder = move_project(project_folder)
    success = yield from 编译Latex(..., main_file_original='merge', main_file_modified='merge_translate_zh', ...)
```

Plugin registration in `crazy_functional.py`:

```python
"Latex英文纠错+高亮修正位置 [需Latex]": {
    "Function": HotReload(Latex英文纠错加PDF对比),
},
"📚Arxiv论文精细翻译（输入arxivID）[需Latex]": {
    "Info": "ArXiv论文精细翻译 | 输入参数arxiv论文的ID，比如1812.10695",
    "Function": HotReload(Latex翻译中文并重新编译PDF),
    "Class": Arxiv_Localize,
},
"📚本地Latex论文精细翻译（上传Latex项目）[需Latex]": {
    "Info": "本地Latex论文精细翻译 | 输入参数是路径",
    "Function": HotReload(Latex翻译中文并重新编译PDF),
},
"PDF翻译中文并重新编译PDF（上传PDF）[需Latex]": {
    "Info": "PDF翻译中文，并重新编译PDF | 输入参数为路径",
    "Function": HotReload(PDF翻译中文并重新编译PDF),
    "Class": PDF_Localize,
}
```

General Gradio dispatch and upload flow:

```python
click_handle = functional[k]["Button"].click(fn=ArgsGeneralWrapper(predict), inputs=[*input_combo, gr.State(True), gr.State(k)], outputs=output_combo)
file_upload.upload(on_file_uploaded, [file_upload, chatbot, txt, txt2, checkboxes, cookies], [chatbot, txt, txt2, cookies])
```

```python
def ArgsGeneralWrapper(f):
    def decorated(..., txt: str, txt2: str, ..., plugin_advanced_arg: dict, *args):
        txt_passon = txt
        if txt == "" and txt2 != "":
            txt_passon = txt2
        if len(args) == 0:
            yield from f(txt_passon, llm_kwargs, plugin_kwargs, chatbot_with_cookie, history, system_prompt, request)
```

```python
def on_file_uploaded(...):
    target_path_base = get_upload_folder(user_name, tag=time_tag)
    for file in files:
        file_origin_name = os.path.basename(file.orig_name)
        this_file_path = pj(target_path_base, file_origin_name)
        shutil.move(file.name, this_file_path)
        upload_msg += extract_archive(file_path=this_file_path, dest_dir=this_file_path + ".extract")
    txt, txt2 = target_path_base, ""
    cookies.update({"most_recent_uploaded": {"path": target_path_base, "time": time.time(), "time_str": time_tag}})
    return chatbot, txt, txt2, cookies
```

### Candidate 1 observations

- User-controlled input plausibly reaches `txt` through the Gradio textbox or uploaded files; uploaded files are moved under a per-user upload folder and may be extracted.
- `validate_path_safety(project_folder, chatbot.get_user())` is present before `move_project`.
- The final shell command strings use fixed logical filenames such as `merge`, `merge_translate_zh`, and `merge_diff` for most calls.
- The `latexdiff` command interpolates `work_folder_original`, `work_folder_modified`, and `work_folder`; these are derived from uploaded/downloaded project folders after processing.
- A likely exploitability question is whether any interpolated path, filename, or generated LaTeX project path can contain shell metacharacters after upload, extraction, `descend_to_extracted_folder_if_exist`, and `move_project`.

## Candidate 1 open questions for LLM

1. Reconstruct the precise call chain from Gradio plugin selection/upload or Arxiv ID input to `compile_latex_with_timeout`.
2. Determine whether user-controlled path or filename components can reach the shell command string after `validate_path_safety`, extraction, and `move_project`.
3. Determine whether `main_file_original`, `main_file_modified`, or `compiler` can ever be user-controlled or whether they are fixed constants.
4. Determine whether the `latexdiff` command is reachable in default/proofread modes and whether its interpolated paths can contain shell metacharacters.
5. Identify runtime preconditions: enabled plugin, installed LaTeX tools, uploaded LaTeX/PDF or Arxiv source, OS/shell behavior, and path validation behavior.

## Candidate 2 static context

### Sink function

Location: `crazy_functions/rag_fns/rag_file_support.py:1-29`

```python
import subprocess
import os

supports_format = ['.csv', '.docx', '.epub', '.ipynb',  '.mbox', '.md', '.pdf',  '.txt', '.ppt', '.pptm', '.pptx', '.bat']

def convert_to_markdown(file_path: str) -> str:
    _, ext = os.path.splitext(file_path.lower())

    if ext in ['.docx', '.doc', '.pptx', '.ppt', '.pptm', '.xls', '.xlsx', '.csv', 'pdf']:
        try:
            md_path = os.path.splitext(file_path)[0] + '.md'
            command = f"markitdown {file_path} > {md_path}"
            subprocess.run(command, shell=True, check=True)
            return md_path
        except Exception as e:
            return file_path

    return file_path
```

### Direct call sites found by `rg`

- `crazy_functions/Document_Optimize.py:97`: `file_path = convert_to_markdown(file_path)`
- `crazy_functions/paper_fns/reduce_aigc.py:154`: `file_path = convert_to_markdown(file_path)`
- Imports at `crazy_functions/Document_Optimize.py:11`, `crazy_functions/Document_Optimize.py:96`, and `crazy_functions/paper_fns/reduce_aigc.py:11`

### Calling functions

`Document_Optimize.py`:

```python
def process_file(self, file_path: str) -> Generator:
    self.chatbot.append(["开始处理文件", f"文件路径: {file_path}"])
    try:
        from crazy_functions.rag_fns.rag_file_support import convert_to_markdown
        file_path = convert_to_markdown(file_path)
        is_paper_format = any(file_path.lower().endswith(ext) for ext in self.paper_extractor.SUPPORTED_EXTENSIONS)
        if is_paper_format:
            return (yield from self._process_structured_paper(file_path))
        else:
            return (yield from self._process_regular_file(file_path))
```

```python
def 自定义智能文档处理(txt: str, llm_kwargs: Dict, plugin_kwargs: Dict, chatbot: List, history: List, system_prompt: str, user_request: str):
    processor = DocumentProcessor(llm_kwargs, plugin_kwargs, chatbot, history, system_prompt)
    if not os.path.exists(txt):
        report_exception(...)
        return
    user_name = chatbot.get_user()
    validate_path_safety(txt, user_name)
    if os.path.isfile(txt):
        file_paths = [txt]
    else:
        project_folder = txt
        extract_folder = next((d for d in glob.glob(f'{project_folder}/*') if os.path.isdir(d) and d.endswith('.extract')), project_folder)
        file_paths = [f for f in glob.glob(f'{extract_folder}/**', recursive=True) if os.path.isfile(f) and not re.search(exclude_patterns, f)]
        file_paths = [f for f in file_paths if any(f.lower().endswith(ext) for ext in list(processor.paper_extractor.SUPPORTED_EXTENSIONS) + ['.json', '.csv', '.xlsx', '.xls'])]
    file_to_process = file_paths[0]
    processed_content = yield from processor.process_file(file_to_process)
```

`paper_fns/reduce_aigc.py`:

```python
def process_file(self, file_path: str) -> Generator:
    self.chatbot.append(["开始处理文件", f"文件路径: {file_path}"])
    try:
        file_path = convert_to_markdown(file_path)
        is_paper_format = any(file_path.lower().endswith(ext) for ext in self.paper_extractor.SUPPORTED_EXTENSIONS)
        if is_paper_format:
            return (yield from self._process_structured_paper(file_path))
        else:
            return (yield from self._process_regular_file(file_path))
```

```python
def 学术降重(txt: str, llm_kwargs: Dict, plugin_kwargs: Dict, chatbot: List, history: List, system_prompt: str, user_request: str):
    processor = DocumentProcessor(llm_kwargs, plugin_kwargs, chatbot, history, system_prompt)
    if not os.path.exists(txt):
        report_exception(...)
        return
    user_name = chatbot.get_user()
    validate_path_safety(txt, user_name)
    if os.path.isfile(txt):
        file_paths = [txt]
    else:
        project_folder = txt
        extract_folder = next((d for d in glob.glob(f'{project_folder}/*') if os.path.isdir(d) and d.endswith('.extract')), project_folder)
        file_paths = [f for f in glob.glob(f'{extract_folder}/**', recursive=True) if os.path.isfile(f) and not re.search(exclude_patterns, f)]
        file_paths = [f for f in file_paths if any(f.lower().endswith(ext) for ext in list(processor.paper_extractor.SUPPORTED_EXTENSIONS) + ['.json', '.csv', '.xlsx', '.xls'])]
    file_to_process = file_paths[0]
    processed_content = yield from processor.process_file(file_to_process)
```

### Entrypoint status observed by `rg`

- `crazy_functional.py:691-705` contains a commented-out registration block for `自定义智能文档处理`.
- `rg` found `def 学术降重(...)` in `paper_fns/reduce_aigc.py`, but no direct active registration in `crazy_functional.py` was found in this pass.
- General Gradio upload and dispatch still apply if these functions are registered through another path not captured here.

### Candidate 2 observations

- The sink command uses raw `file_path` and derived `md_path` without shell quoting: `markitdown {file_path} > {md_path}`.
- The extension filter includes `.docx`, `.doc`, `.pptx`, `.ppt`, `.pptm`, `.xls`, `.xlsx`, `.csv`, and the string `pdf` without a dot.
- If the plugin entrypoint is reachable and a user can control uploaded file names/paths, shell metacharacters in `file_path` may be relevant.
- `on_file_uploaded` preserves `os.path.basename(file.orig_name)` when moving uploads, then extracts archives to `<uploaded-file>.extract`.
- `validate_path_safety(txt, user_name)` checks the top-level input path before enumerating nested files; LLM should inspect whether it constrains nested extracted filenames.

## Candidate 2 open questions for LLM

1. Determine whether `自定义智能文档处理` or `学术降重` is reachable through active plugin registration, custom plugin loading, or another runtime path.
2. If reachable, reconstruct the call chain from upload/text input to `convert_to_markdown`.
3. Determine whether uploaded file names or extracted archive member names can include shell metacharacters on supported deployment platforms.
4. Determine whether `validate_path_safety` constrains only the top-level `txt` path or also nested `file_to_process` values.
5. Identify runtime preconditions: plugin availability, `markitdown` binary availability, supported file extension, upload/extraction behavior, and OS shell behavior.

## Instructions for LLM

- Use only the static context in this document.
- Determine whether user-controlled input reaches a `shell=True` command for each candidate.
- Reconstruct the most likely call chain from HTTP/API/plugin entrypoint to sink.
- Identify required runtime preconditions.
- Propose PoC shape only; do not execute commands.
- Classify each candidate as one of: `likely exploitable`, `likely false positive`, or `needs more context`.
- Do not invent missing routes, plugin registrations, parameters, or sanitizer behavior.
- Do not write a final confirmed verdict. Before dynamic verifier execution, all findings remain unconfirmed.
