# gpt_academic RCE Call Chain Reconstruction Prompt

You are reviewing offline static context for two Semgrep RCE candidates in `gpt_academic`.

Do not execute code. Do not call tools. Do not assume routes, plugin registrations, parameters, sanitizer behavior, or deployment settings that are not present in the provided context.

Dynamic verification has not run. You must not write `confirmed` or otherwise claim exploit confirmation. All findings are unconfirmed until a verifier PoC succeeds.

## Input context

Use only `docs/gpt_academic_rce_callchain_context.md` as the evidence source.

## Task

For each candidate:

1. Determine whether user-controlled input can reach a `shell=True` command.
2. Reconstruct the call chain from HTTP/API/plugin entrypoint to the sink.
3. Identify runtime preconditions needed for exploitation.
4. Propose the shape of a PoC only. Do not execute anything.
5. Classify the candidate as `likely exploitable`, `likely false positive`, or `needs more context`.
6. List missing context that must be checked before dynamic verification.

## Required output format

Return Markdown with one section per candidate. Each section must include this JSON block:

```json
{
  "candidate_id": "C1 or C2",
  "call_chain": [
    {
      "step": 1,
      "location": "file:line or unknown",
      "function": "function or method name",
      "data": "input/output value being passed",
      "evidence": "brief quote or paraphrase from context"
    }
  ],
  "user_control_analysis": {
    "source": "textbox/upload/archive/arxiv/custom plugin/unknown",
    "controlled_values": ["value names"],
    "sanitizers_or_guards": ["observed checks"],
    "can_reach_shell": true,
    "reasoning": "short static reasoning"
  },
  "runtime_preconditions": [
    "condition"
  ],
  "poc_shape": {
    "goal": "what the PoC would try to prove",
    "input_vector": "upload filename/path/textbox/etc.",
    "payload_shape": "high-level payload description only, no destructive command",
    "expected_observable": "what verifier should observe"
  },
  "confidence": "high|medium|low",
  "classification": "likely exploitable|likely false positive|needs more context",
  "missing_context": [
    "specific missing fact"
  ],
  "recommended_next_step": "next static or dynamic step"
}
```

## Candidate IDs

- `C1`: `crazy_functions/latex_fns/latex_toolbox.py:599`, `compile_latex_with_timeout`
- `C2`: `crazy_functions/rag_fns/rag_file_support.py:22`, `convert_to_markdown`

## Hard constraints

- Do not produce a final verdict of `confirmed`.
- Do not claim CVE readiness.
- Do not invent a route or plugin registration when the context says it is missing or commented out.
- Do not recommend running commands outside an isolated verifier container.
- Keep PoC details at the shape level; actual PoC commands should be drafted separately for verifier review.
