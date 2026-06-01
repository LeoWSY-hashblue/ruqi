# First RCE Candidate Audit - gpt_academic

This is the final audit summary for the first two Semgrep RCE candidates
observed in `gpt_academic`. It is not a confirmed-vulnerability report.

## Target

- Target repo path: `E:\tool\gpt_academic`
- Target commit: `d6bde0fa54373309bd05823a49bda8da019d2c77`
- Candidate count: 2
- Dynamic verification: Not run
- Confirmed findings: 0
- CVE-ready findings: 0

## Final Conclusion

No candidate in this audit is confirmed. Both candidates remain unsuitable for a
CVE report unless future evidence finds a concrete user-controlled path into the
shell command and verifier execution confirms canary modification or deletion.

## Candidate Summary

| Candidate | Sink | Final audit status | Reason |
| --- | --- | --- | --- |
| C1 | `compile_latex_with_timeout(command, shell=True)` | `likely false positive` | Active LaTeX chain reaches `shell=True`, but no proven user-controlled shell metacharacters enter the observed command strings. |
| C2 | `convert_to_markdown(file_path)` | `likely false positive / unreachable` | Sink exists and would be unsafe if reachable, but no active registered UI/plugin route was found. |

## Supporting Reviews

- [Static call-chain context](gpt_academic_rce_callchain_context.md)
- [Reviewed LLM-assisted analysis](gpt_academic_rce_llm_analysis.md)
- [C1 path-control review](gpt_academic_c1_path_control_review.md)
- [C2 reachability review](gpt_academic_c2_reachability_review.md)

## Original Candidate Inventory

### Candidate 1

- file: `crazy_functions/latex_fns/latex_toolbox.py`
- line: 599
- sink_type: `rce`
- semgrep_rule_id: `python.lang.security.audit.subprocess-shell-true.subprocess-shell-true`
- enclosing_symbol: `compile_latex_with_timeout`
- final audit status: `not confirmed`
- final classification: `likely false positive`
- audit note: Active plugin flow can reach the sink, but static review did not
  prove that uploaded filenames, archive member names, or other user-controlled
  shell metacharacters survive into the shell command string.
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
- final audit status: `not confirmed`
- final classification: `likely false positive / unreachable`
- audit note: The sink is unsafe if invoked with a user-controlled path, but
  current static review found no active registered route to the relevant
  `Document_Optimize` or `reduce_aigc` entrypoints.
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

## Next Step

Do not prepare a CVE report from these candidates. Only reopen dynamic verifier
work if new static evidence identifies a concrete active route with
user-controlled shell metacharacters reaching one of the command strings.
