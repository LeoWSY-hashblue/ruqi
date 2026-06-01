# First RCE Candidate Report

This report is a reproducible candidate inventory. Findings are unconfirmed until verifier execution succeeds.

## Target

- Target repo path: `E:\tool\gpt_academic`
- Target commit: `d6bde0fa54373309bd05823a49bda8da019d2c77`
- Generated timestamp: `2026-06-01T08:33:16.971220Z`
- Candidate count: 2
- Verification Status: Not run
- LLM Call Chain Reconstruction: Not run

## Candidates

### Candidate 1

- file: `crazy_functions/latex_fns/latex_toolbox.py`
- line: 599
- sink_type: `rce`
- semgrep_rule_id: `python.lang.security.audit.subprocess-shell-true.subprocess-shell-true`
- enclosing_symbol: `compile_latex_with_timeout`
- code_snippet:

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
```

### Candidate 2

- file: `crazy_functions/rag_fns/rag_file_support.py`
- line: 22
- sink_type: `rce`
- semgrep_rule_id: `python.lang.security.audit.subprocess-shell-true.subprocess-shell-true`
- enclosing_symbol: `convert_to_markdown`
- code_snippet:

```python
        try:
            # 创建输出Markdown文件路径
            md_path = os.path.splitext(file_path)[0] + '.md'
            # 使用markitdown工具将文件转换为Markdown
            command = f"markitdown {file_path} > {md_path}"
            subprocess.run(command, shell=True, check=True)
            print(f"已将{ext}文件转换为Markdown: {md_path}")
            return md_path
        except Exception as e:
            print(f"{ext}转Markdown失败: {str(e)}，将继续处理原文件")
            return file_path
```

## Next Manual Verification Plan

1. Use an LLM to reconstruct the call chain from HTTP/API/plugin entrypoints to each sink.
2. Draft a PoC for each candidate.
3. Run the verifier in an isolated Docker container.
4. Move only confirmed findings into a CVE report.
