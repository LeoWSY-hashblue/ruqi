# gpt_academic RCE Call Chain Reconstruction

LLM-assisted draft, human-reviewed corrections applied.

Dynamic verification has not run. All findings in this document are unconfirmed.

## Human review notes

- The original LLM draft overclaimed C1 user control by listing `main_file_original` and `main_file_modified` as user-controlled. Static review shows these are fixed logical names at the observed call sites.
- The original LLM draft overclaimed C2 reachability by setting `can_reach_shell: true`. Static review did not find active registration for the relevant C2 entrypoints in `crazy_functional.py`.
- This revision uses deterministic static evidence only. It does not claim exploit confirmation.

## Candidate 1

```json
{
  "candidate_id": "C1",
  "call_chain": [
    {
      "step": 1,
      "location": "main.py:238 and toolbox.py:93-149",
      "function": "ArgsGeneralWrapper(predict)",
      "data": "txt/txt2 -> txt_passon",
      "evidence": "Plugin button clicks are wrapped by ArgsGeneralWrapper. It passes txt, or txt2 when txt is empty, into the selected plugin."
    },
    {
      "step": 2,
      "location": "toolbox.py:511-574",
      "function": "on_file_uploaded",
      "data": "uploaded files -> target_path_base -> txt/txt2",
      "evidence": "Uploaded files are moved into get_upload_folder(user, tag), archives are extracted, and txt is set to target_path_base unless the floating input area swaps txt/txt2."
    },
    {
      "step": 3,
      "location": "crazy_functional.py:342-383",
      "function": "registered LaTeX plugins",
      "data": "txt/txt2 path or Arxiv ID -> LaTeX plugin",
      "evidence": "LaTeX correction, Arxiv translation, local LaTeX translation, and PDF-to-LaTeX translation plugins are actively registered."
    },
    {
      "step": 4,
      "location": "Latex_Function.py:331-424",
      "function": "Latex翻译中文并重新编译PDF",
      "data": "txt -> project_folder -> move_project(project_folder, arxiv_id)",
      "evidence": "The function accepts txt, optionally downloads/extracts Arxiv source, validates project_folder with validate_path_safety, copies it to a generated work folder, then calls 编译Latex."
    },
    {
      "step": 5,
      "location": "Latex_Function.py:303-308, 421-424, 573-578",
      "function": "编译Latex",
      "data": "fixed main_file_original/main_file_modified plus project_folder-derived work folders",
      "evidence": "Observed calls pass fixed logical names such as merge, merge_proofread_en, and merge_translate_zh. The work_folder* values come from project_folder after validate_path_safety and move_project."
    },
    {
      "step": 6,
      "location": "latex_actions.py:374-428",
      "function": "compile_latex_with_timeout",
      "data": "compile command strings",
      "evidence": "get_compile_command builds '<compiler> -interaction=batchmode -file-line-error <filename>.tex'. Additional bibtex and latexdiff commands are passed to compile_latex_with_timeout."
    },
    {
      "step": 7,
      "location": "latex_toolbox.py:595-608",
      "function": "subprocess.Popen",
      "data": "command",
      "evidence": "compile_latex_with_timeout executes subprocess.Popen(command, shell=True, ...)."
    }
  ],
  "user_control_analysis": {
    "source": "textbox, uploaded files, extracted archives, or Arxiv ID",
    "controlled_values": [
      "txt/txt2 before plugin dispatch",
      "uploaded original file names under target_path_base",
      "archive contents before project normalization",
      "project_folder before move_project"
    ],
    "not_proven_user_controlled": [
      "main_file_original",
      "main_file_modified",
      "compiler",
      "generated work_folder after move_project"
    ],
    "sanitizers_or_guards": [
      "validate_path_safety(project_folder, chatbot.get_user()) only allows paths under PATH_PRIVATE_UPLOAD, PATH_LOGGING, tests, or build and checks allowed user prefixes",
      "move_project copies the project into get_log_folder()/gen_time_str() or ARXIV_CACHE_DIR/<arxiv_id>/workfolder"
    ],
    "can_reach_shell": "not proven",
    "reasoning": "The active LaTeX plugin call chain reaches shell=True. However, the observed command filename arguments are fixed logical names and the project is copied to a generated work folder before compilation. Static review has not proven that user-controlled shell metacharacters survive into command strings. The latexdiff command interpolates work_folder paths, so path-control behavior after validate_path_safety, descend_to_extracted_folder_if_exist, and move_project remains the key validation point."
  },
  "runtime_preconditions": [
    "A registered LaTeX plugin is invoked",
    "A valid LaTeX/PDF/Arxiv input reaches the plugin",
    "LaTeX tooling such as pdflatex/xelatex/bibtex/latexdiff is installed",
    "The vulnerable command path is reached, especially latexdiff for non-translate_zh modes if path control is the intended vector"
  ],
  "poc_shape": {
    "goal": "Determine whether any user-controlled path component can survive into a shell=True command and modify a verifier canary.",
    "input_vector": "Controlled upload/archive/LaTeX project path or file naming, tested only inside an isolated verifier container.",
    "payload_shape": "A benign shell metacharacter canary-touch payload embedded in the narrowest path or filename component that static review shows reaches the command string.",
    "expected_observable": "Verifier should observe canary deletion or modification only if the payload reaches shell execution."
  },
  "confidence": "medium-low",
  "classification": "needs more context",
  "missing_context": [
    "Exact behavior of extract_archive with archive member names containing shell metacharacters",
    "Whether uploaded or extracted directory names can affect project_folder after descend_to_extracted_folder_if_exist",
    "Whether move_project's generated destination path eliminates user-controlled path components from work_folder*",
    "Whether any non-observed call site passes user-controlled main_file_original or main_file_modified",
    "Whether latexdiff mode is reachable from an active plugin with user-controlled work_folder values"
  ],
  "recommended_next_step": "Perform targeted static review of extract_archive, descend_to_extracted_folder_if_exist, move_project, and all 编译Latex call sites. Only then draft a verifier PoC for the narrowest path-control hypothesis."
}
```

## Candidate 2

```json
{
  "candidate_id": "C2",
  "call_chain": [
    {
      "step": 1,
      "location": "crazy_functions/Document_Optimize.py:611-660",
      "function": "自定义智能文档处理 -> DocumentProcessor.process_file",
      "data": "txt -> file_to_process -> convert_to_markdown",
      "evidence": "The code path exists and passes file_to_process to process_file, which calls convert_to_markdown."
    },
    {
      "step": 2,
      "location": "crazy_functions/paper_fns/reduce_aigc.py:787-854",
      "function": "学术降重 -> DocumentProcessor.process_file",
      "data": "txt -> file_to_process -> convert_to_markdown",
      "evidence": "The code path exists and passes file_to_process to process_file, which calls convert_to_markdown."
    },
    {
      "step": 3,
      "location": "crazy_functions/rag_fns/rag_file_support.py:6-29",
      "function": "convert_to_markdown",
      "data": "file_path -> command",
      "evidence": "If called with a supported extension, convert_to_markdown builds command = f'markitdown {file_path} > {md_path}' and executes subprocess.run(command, shell=True, check=True)."
    }
  ],
  "user_control_analysis": {
    "source": "not currently proven reachable",
    "controlled_values": [
      "file_path would be relevant if an active plugin or other runtime route reaches these functions"
    ],
    "sanitizers_or_guards": [
      "Document_Optimize and reduce_aigc both call validate_path_safety(txt, user_name) before enumerating files",
      "Nested file_to_process values are selected from glob results under txt or an .extract directory"
    ],
    "can_reach_shell": "not proven",
    "reasoning": "Static review confirms the sink and internal call paths exist, but did not find active crazy_functional.py registration for Document_Optimize or 学术降重. The Document_Optimize registration block is commented out, and rg did not find an active reduce_aigc/学术降重 registration in crazy_functional.py. Therefore reachability from the normal plugin UI is not currently proven."
  },
  "runtime_preconditions": [
    "An active route must exist to 自定义智能文档处理, 学术降重, or another caller of convert_to_markdown",
    "markitdown must be installed and executable",
    "The selected file must have one of the extensions handled by convert_to_markdown",
    "A user-controlled filename or path component must survive upload/extraction and path validation"
  ],
  "poc_shape": {
    "goal": "Only if reachability is proven, test whether a controlled file_path can influence the shell=True markitdown command.",
    "input_vector": "Potential uploaded file or archive member name, pending active-route proof.",
    "payload_shape": "A benign canary-touch shell metacharacter payload in a filename/path component, executed only inside an isolated verifier container.",
    "expected_observable": "Verifier should observe canary deletion or modification only if an active route reaches convert_to_markdown and the shell metacharacter is interpreted."
  },
  "confidence": "medium",
  "classification": "likely unreachable in current registration state / needs more context",
  "missing_context": [
    "Any active registration or dynamic plugin path for 自定义智能文档处理",
    "Any active registration or dynamic plugin path for 学术降重",
    "Whether another registered plugin imports and calls convert_to_markdown",
    "Archive extraction filename behavior and path validation coverage for nested files"
  ],
  "recommended_next_step": "Do not draft a dynamic PoC for C2 until an active route is found. First search runtime plugin loading paths and registered plugin dictionaries beyond crazy_functional.py."
}
```
