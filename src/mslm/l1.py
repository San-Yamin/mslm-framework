"""L1 merchant onboarding analysis for Python mini-app samples."""

import ast
import hashlib
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Set, Tuple

from .risk import CCRSResult, calculate_ccrs


CVSS_BY_VULNERABILITY = {
    "V1": 7.5,
    "V2": 6.5,
    "V3": 8.1,
    "V4": 5.9,
    "V5": 6.2,
    "V6": 7.2,
}


@dataclass(frozen=True)
class Finding:
    finding_id: str
    vulnerability_id: str
    rule_id: str
    cvss: float
    line: int
    message: str


@dataclass(frozen=True)
class OnboardingDecision:
    approved: bool
    findings: Tuple[Finding, ...]
    risk: Optional[CCRSResult]
    parse_error: Optional[str] = None


class _RuleVisitor(ast.NodeVisitor):
    def __init__(self, source_hash: str) -> None:
        self.source_hash = source_hash
        self.findings: Dict[Tuple[str, int], Finding] = {}
        self.function_stack: List[str] = []

    def _add(self, vulnerability: str, rule: str, node: ast.AST, message: str) -> None:
        line = getattr(node, "lineno", 0)
        key = (rule, line)
        digest = hashlib.sha256(
            f"{self.source_hash}:{vulnerability}:{rule}:{line}".encode("utf-8")
        ).hexdigest()[:16]
        self.findings[key] = Finding(
            finding_id=digest,
            vulnerability_id=vulnerability,
            rule_id=rule,
            cvss=CVSS_BY_VULNERABILITY[vulnerability],
            line=line,
            message=message,
        )

    @staticmethod
    def _name(node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            prefix = _RuleVisitor._name(node.value)
            return f"{prefix}.{node.attr}" if prefix else node.attr
        return ""

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        lowered = node.name.lower()
        self.function_stack.append(lowered)
        if "custom_auth" in lowered or lowered.startswith("verify_otp"):
            self._add("V1", "L1.AUTH.CUSTOM", node, "Custom authentication flow requires review")
        if any(word in lowered for word in ("admin", "delete", "refund")):
            calls = {
                self._name(child.func)
                for child in ast.walk(node)
                if isinstance(child, ast.Call)
            }
            if not any("authoriz" in call or "permission" in call for call in calls):
                self._add(
                    "V6",
                    "L1.AUTHZ.MISSING",
                    node,
                    "Sensitive handler has no visible authorization call",
                )
        self.generic_visit(node)
        self.function_stack.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Call(self, node: ast.Call) -> None:
        name = self._name(node.func).lower()
        if name in {"hashlib.md5", "hashlib.sha1", "random.randint", "random.random"}:
            self._add("V4", "L1.CRYPTO.WEAK", node, f"Weak security primitive: {name}")
        if name.endswith((".json", ".dict")) and self.function_stack:
            self._add(
                "V5",
                "L1.DATA.BULK_RESPONSE",
                node,
                "Bulk object serialization requires sensitive-field review",
            )
        self.generic_visit(node)

    def visit_Compare(self, node: ast.Compare) -> None:
        nodes: Iterable[ast.AST] = (node.left, *node.comparators)
        if any(
            isinstance(item, ast.Constant)
            and isinstance(item.value, str)
            and ("password" in self._name(node.left).lower() or len(item.value) >= 4)
            for item in nodes
        ) and "auth" in " ".join(self.function_stack):
            self._add("V1", "L1.AUTH.HARDCODED_SECRET", node, "Hard-coded authentication value")
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        base = self._name(node.value).lower()
        rendered = ast.unparse(node).lower() if hasattr(ast, "unparse") else base
        if any(term in rendered for term in ("request", "payload", "body")) and any(
            term in rendered for term in ("price", "amount")
        ):
            self._add("V3", "L1.PRICE.CLIENT_CONTROLLED", node, "Price read from client input")
        if any(term in rendered for term in ("transaction_id", "account_id")):
            self._add("V2", "L1.IDOR.REFERENCE", node, "Direct object reference requires ownership check")
        self.generic_visit(node)


class OnboardingAuditor:
    def __init__(self, approval_threshold: float = 7.0) -> None:
        if not 0.0 <= approval_threshold <= 10.0:
            raise ValueError("approval_threshold must be in [0, 10]")
        self.approval_threshold = approval_threshold

    def analyze(self, source: str) -> OnboardingDecision:
        source_hash = hashlib.sha256(source.encode("utf-8")).hexdigest()
        try:
            tree = ast.parse(source)
        except SyntaxError as exc:
            return OnboardingDecision(False, (), None, f"{exc.msg} at line {exc.lineno}")
        visitor = _RuleVisitor(source_hash)
        visitor.visit(tree)
        findings = tuple(sorted(visitor.findings.values(), key=lambda item: (item.line, item.rule_id)))
        if not findings:
            return OnboardingDecision(True, (), None)
        risk = calculate_ccrs(finding.cvss for finding in findings)
        return OnboardingDecision(risk.deployment_score < self.approval_threshold, findings, risk)

