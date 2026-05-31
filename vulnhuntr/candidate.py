from dataclasses import dataclass
from typing import Literal

SinkType = Literal["rce", "ssrf", "sqli", "path_traversal"]


@dataclass(frozen=True)
class Candidate:
    file: str
    line: int
    sink_type: SinkType
    semgrep_rule_id: str
    code_snippet: str
    enclosing_symbol: str
    enclosing_source: str
