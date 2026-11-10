#!/usr/bin/env python3
"""
SpecGate Core Deterministic Engine (Preparação Local Segura para o Experimento EXP-H1).

Motor 100% determinístico (zero chamadas de LLM) para detecção de Breaking Changes,
cálculo de incremento SemVer (MAJOR / MINOR / PATCH) e validação de política de
depreciação (RFC 8594 Sunset) em contratos OpenAPI 3.x / JSON Schema.
"""

import argparse
import hashlib
import html
import json
import sys
from typing import Any, Dict, List, Optional, Set, Tuple


class SpecGateEngine:
    """Compara duas especificações OpenAPI 3.x (dicionários Python carregados de JSON/YAML)."""

    HTTP_METHODS = {"get", "post", "put", "delete", "patch", "options", "head"}

    def compare_specs(self, base_spec: Dict[str, Any], head_spec: Dict[str, Any]) -> Dict[str, Any]:
        breaking_changes: List[Dict[str, Any]] = []
        non_breaking_changes: List[Dict[str, Any]] = []

        base_paths = base_spec.get("paths", {}) or {}
        head_paths = head_spec.get("paths", {}) or {}

        for path, base_path_item in base_paths.items():
            if path not in head_paths:
                loc = f"paths.{path}"
                breaking_changes.append(
                    {
                        "rule_id": "OAS-BREAK-001",
                        "severity": "BREAKING",
                        "location": loc,
                        "json_path": loc,
                        "message": f"Endpoint path '{path}' foi removido integralmente.",
                    }
                )
                continue

            head_path_item = head_paths[path]
            for method in self.HTTP_METHODS:
                if method not in base_path_item:
                    continue
                if method not in head_path_item:
                    was_deprecated = bool(base_path_item[method].get("deprecated", False))
                    rule_id = "OAS-BREAK-002" if was_deprecated else "OAS-BREAK-003"
                    loc = f"paths.{path}.{method}"
                    breaking_changes.append(
                        {
                            "rule_id": rule_id,
                            "severity": "BREAKING",
                            "location": loc,
                            "json_path": loc,
                            "message": (
                                f"Operação '{method.upper()} {path}' foi removida "
                                f"({'com' if was_deprecated else 'SEM'} marcação prévia de deprecated)."
                            ),
                        }
                    )
                    continue

                self._compare_operation(
                    path,
                    method,
                    base_path_item[method],
                    head_path_item[method],
                    breaking_changes,
                    non_breaking_changes,
                )

        # Detectar novos endpoints adicionados (MINOR)
        for path, head_path_item in head_paths.items():
            if path not in base_paths:
                loc = f"paths.{path}"
                non_breaking_changes.append(
                    {
                        "rule_id": "OAS-INFO-001",
                        "severity": "NON_BREAKING",
                        "location": loc,
                        "json_path": loc,
                        "message": f"Novo endpoint path '{path}' adicionado.",
                    }
                )
            else:
                base_path_item = base_paths[path]
                for method in self.HTTP_METHODS:
                    if method in head_path_item and method not in base_path_item:
                        loc = f"paths.{path}.{method}"
                        non_breaking_changes.append(
                            {
                                "rule_id": "OAS-INFO-002",
                                "severity": "NON_BREAKING",
                                "location": loc,
                                "json_path": loc,
                                "message": f"Nova operação '{method.upper()} {path}' adicionada.",
                            }
                        )

        recommended_bump = (
            "MAJOR"
            if breaking_changes
            else ("MINOR" if non_breaking_changes else "PATCH")
        )

        full_pair_hash = hashlib.sha256(
            (
                json.dumps(base_spec, sort_keys=True)
                + "::"
                + json.dumps(head_spec, sort_keys=True)
            ).encode("utf-8")
        ).hexdigest()
        spec_pair_hash = full_pair_hash[:16]
        gate_passed = len(breaking_changes) == 0
        verdict = "PASS" if gate_passed else "FAIL_BREAKING_CHANGE"

        return {
            "gate_passed": gate_passed,
            "verdict": verdict,
            "recommended_semver_bump": recommended_bump,
            "breaking_changes_count": len(breaking_changes),
            "non_breaking_changes_count": len(non_breaking_changes),
            "additive_changes_count": len(non_breaking_changes),
            "breaking_changes": breaking_changes,
            "non_breaking_changes": non_breaking_changes,
            "audit_fingerprint": f"SG-{spec_pair_hash.upper()}",
            "audit_sha256": full_pair_hash,
        }

    def _compare_operation(
        self,
        path: str,
        method: str,
        base_op: Dict[str, Any],
        head_op: Dict[str, Any],
        breaking: List[Dict[str, Any]],
        non_breaking: List[Dict[str, Any]],
    ) -> None:
        # 1. Comparar parâmetros (query, header, path)
        base_params = {(p.get("name"), p.get("in")): p for p in base_op.get("parameters", []) or []}
        head_params = {(p.get("name"), p.get("in")): p for p in head_op.get("parameters", []) or []}

        for key, hp in head_params.items():
            name, loc = key
            param_path = f"paths.{path}.{method}.parameters.{loc}.{name}"
            if key not in base_params:
                if hp.get("required", False):
                    breaking.append(
                        {
                            "rule_id": "OAS-BREAK-004",
                            "severity": "BREAKING",
                            "location": param_path,
                            "json_path": param_path,
                            "message": f"Novo parâmetro obrigatório '{name}' ({loc}) adicionado na requisição.",
                        }
                    )
                else:
                    non_breaking.append(
                        {
                            "rule_id": "OAS-INFO-003",
                            "severity": "NON_BREAKING",
                            "location": param_path,
                            "json_path": param_path,
                            "message": f"Novo parâmetro opcional '{name}' ({loc}) adicionado.",
                        }
                    )
            else:
                bp = base_params[key]
                if not bp.get("required", False) and hp.get("required", False):
                    breaking.append(
                        {
                            "rule_id": "OAS-BREAK-005",
                            "severity": "BREAKING",
                            "location": param_path,
                            "json_path": param_path,
                            "message": f"Parâmetro opcional '{name}' ({loc}) tornou-se obrigatório.",
                        }
                    )
                b_type = (bp.get("schema") or {}).get("type")
                h_type = (hp.get("schema") or {}).get("type")
                if b_type and h_type and b_type != h_type:
                    breaking.append(
                        {
                            "rule_id": "OAS-BREAK-006",
                            "severity": "BREAKING",
                            "location": param_path,
                            "json_path": param_path,
                            "message": f"Tipo do parâmetro '{name}' alterado de '{b_type}' para '{h_type}'.",
                        }
                    )

        # 2. Comparar Request Body (application/json)
        base_req_schema = self._extract_json_schema(base_op.get("requestBody"))
        head_req_schema = self._extract_json_schema(head_op.get("requestBody"))
        if base_req_schema and head_req_schema:
            self._compare_request_schema(
                f"paths.{path}.{method}.requestBody",
                base_req_schema,
                head_req_schema,
                breaking,
                non_breaking,
            )

        # 3. Comparar Responses (2xx)
        base_resps = base_op.get("responses", {}) or {}
        head_resps = head_op.get("responses", {}) or {}
        for status_code, b_resp in base_resps.items():
            if not str(status_code).startswith("2"):
                continue
            if status_code not in head_resps:
                resp_path = f"paths.{path}.{method}.responses.{status_code}"
                breaking.append(
                    {
                        "rule_id": "OAS-BREAK-007",
                        "severity": "BREAKING",
                        "location": resp_path,
                        "json_path": resp_path,
                        "message": f"Código de resposta de sucesso '{status_code}' foi removido.",
                    }
                )
                continue
            b_schema = self._extract_json_schema(b_resp)
            h_schema = self._extract_json_schema(head_resps[status_code])
            if b_schema and h_schema:
                self._compare_response_schema(
                    f"paths.{path}.{method}.responses.{status_code}",
                    b_schema,
                    h_schema,
                    breaking,
                    non_breaking,
                )

    @staticmethod
    def _extract_json_schema(container: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if not container:
            return None
        content = container.get("content", {}) or {}
        app_json = content.get("application/json", {}) or {}
        return app_json.get("schema")

    def _compare_request_schema(
        self,
        loc: str,
        base_s: Dict[str, Any],
        head_s: Dict[str, Any],
        breaking: List[Dict[str, Any]],
        non_breaking: List[Dict[str, Any]],
    ) -> None:
        b_req: Set[str] = set(base_s.get("required", []) or [])
        h_req: Set[str] = set(head_s.get("required", []) or [])
        added_req = h_req - b_req
        for prop in sorted(added_req):
            prop_path = f"{loc}.required.{prop}"
            breaking.append(
                {
                    "rule_id": "OAS-BREAK-008",
                    "severity": "BREAKING",
                    "location": prop_path,
                    "json_path": prop_path,
                    "message": f"Nova propriedade obrigatória '{prop}' adicionada ao payload de requisição.",
                }
            )

        b_props = base_s.get("properties", {}) or {}
        h_props = head_s.get("properties", {}) or {}
        for prop, b_prop_schema in b_props.items():
            if prop in h_props:
                b_t = b_prop_schema.get("type")
                h_t = h_props[prop].get("type")
                if b_t and h_t and b_t != h_t:
                    prop_path = f"{loc}.properties.{prop}"
                    breaking.append(
                        {
                            "rule_id": "OAS-BREAK-009",
                            "severity": "BREAKING",
                            "location": prop_path,
                            "json_path": prop_path,
                            "message": f"Tipo da propriedade de requisição '{prop}' mudou de '{b_t}' para '{h_t}'.",
                        }
                    )

    def _compare_response_schema(
        self,
        loc: str,
        base_s: Dict[str, Any],
        head_s: Dict[str, Any],
        breaking: List[Dict[str, Any]],
        non_breaking: List[Dict[str, Any]],
    ) -> None:
        b_req: Set[str] = set(base_s.get("required", []) or [])
        h_req: Set[str] = set(head_s.get("required", []) or [])
        removed_req = b_req - h_req
        for prop in sorted(removed_req):
            prop_path = f"{loc}.required.{prop}"
            breaking.append(
                {
                    "rule_id": "OAS-BREAK-010",
                    "severity": "BREAKING",
                    "location": prop_path,
                    "json_path": prop_path,
                    "message": f"Propriedade obrigatória '{prop}' deixou de ser garantida na resposta.",
                }
            )

        b_props = base_s.get("properties", {}) or {}
        h_props = head_s.get("properties", {}) or {}
        for prop, b_prop_schema in b_props.items():
            prop_path = f"{loc}.properties.{prop}"
            if prop not in h_props:
                breaking.append(
                    {
                        "rule_id": "OAS-BREAK-011",
                        "severity": "BREAKING",
                        "location": prop_path,
                        "json_path": prop_path,
                        "message": f"Propriedade '{prop}' foi removida do payload de resposta.",
                    }
                )
            else:
                b_t = b_prop_schema.get("type")
                h_t = h_props[prop].get("type")
                if b_t and h_t and b_t != h_t:
                    breaking.append(
                        {
                            "rule_id": "OAS-BREAK-012",
                            "severity": "BREAKING",
                            "location": prop_path,
                            "json_path": prop_path,
                            "message": f"Tipo da propriedade de resposta '{prop}' mudou de '{b_t}' para '{h_t}'.",
                        }
                    )
        for prop in h_props:
            if prop not in b_props:
                prop_path = f"{loc}.properties.{prop}"
                non_breaking.append(
                    {
                        "rule_id": "OAS-INFO-004",
                        "severity": "NON_BREAKING",
                        "location": prop_path,
                        "json_path": prop_path,
                        "message": f"Nova propriedade '{prop}' adicionada na resposta (retrocompatível).",
                    }
                )

    @staticmethod
    def _normalize_diff_result(diff_result: Dict[str, Any]) -> Dict[str, Any]:
        raw_breaking = diff_result.get("breaking_changes") or []
        raw_non_breaking = diff_result.get("non_breaking_changes") or []

        normalized_breaking: List[Dict[str, str]] = []
        for item in raw_breaking:
            loc = str(item.get("json_path") or item.get("location") or "$")
            normalized_breaking.append(
                {
                    "rule_id": str(item.get("rule_id") or "OAS-BREAK-000"),
                    "severity": str(item.get("severity") or "BREAKING"),
                    "json_path": loc,
                    "location": loc,
                    "message": str(item.get("message") or ""),
                }
            )

        normalized_non_breaking: List[Dict[str, str]] = []
        for item in raw_non_breaking:
            loc = str(item.get("json_path") or item.get("location") or "$")
            normalized_non_breaking.append(
                {
                    "rule_id": str(item.get("rule_id") or "OAS-INFO-000"),
                    "severity": str(item.get("severity") or "NON_BREAKING"),
                    "json_path": loc,
                    "location": loc,
                    "message": str(item.get("message") or ""),
                }
            )

        breaking_count = int(diff_result.get("breaking_changes_count", len(normalized_breaking)))
        additive_count = int(
            diff_result.get(
                "additive_changes_count",
                diff_result.get("non_breaking_changes_count", len(normalized_non_breaking)),
            )
        )

        if "verdict" in diff_result and diff_result["verdict"]:
            verdict = str(diff_result["verdict"])
        elif "gate_passed" in diff_result:
            verdict = "PASS" if bool(diff_result["gate_passed"]) else "FAIL_BREAKING_CHANGE"
        else:
            verdict = "PASS" if breaking_count == 0 else "FAIL_BREAKING_CHANGE"

        semver_bump = str(
            diff_result.get("recommended_semver_bump")
            or ("MAJOR" if breaking_count > 0 else ("MINOR" if additive_count > 0 else "PATCH"))
        )

        audit_sha256 = str(diff_result.get("audit_sha256") or "").strip()
        if not audit_sha256:
            canonical_source = {
                "verdict": verdict,
                "recommended_semver_bump": semver_bump,
                "breaking_changes_count": breaking_count,
                "additive_changes_count": additive_count,
                "breaking_changes": normalized_breaking,
                "non_breaking_changes": normalized_non_breaking,
                "audit_fingerprint": str(diff_result.get("audit_fingerprint") or ""),
            }
            audit_sha256 = hashlib.sha256(
                json.dumps(canonical_source, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest()

        return {
            "verdict": verdict,
            "gate_passed": verdict.upper().startswith("PASS"),
            "recommended_semver_bump": semver_bump,
            "breaking_changes_count": breaking_count,
            "additive_changes_count": additive_count,
            "non_breaking_changes_count": additive_count,
            "breaking_changes": normalized_breaking,
            "non_breaking_changes": normalized_non_breaking,
            "audit_sha256": audit_sha256,
        }

    def generate_pr_comment_markdown(
        self,
        diff_result: Dict[str, Any],
        repo_name: str = "org/repo",
        pr_number: int = 1,
    ) -> str:
        """Gera comentário Markdown rico para Pull Requests no GitHub."""
        norm = self._normalize_diff_result(diff_result)
        verdict = norm["verdict"]
        semver_bump = norm["recommended_semver_bump"]
        breaking_count = norm["breaking_changes_count"]
        additive_count = norm["additive_changes_count"]
        audit_sha256 = norm["audit_sha256"]
        breaking_changes = norm["breaking_changes"]

        status_icon = "✅" if verdict == "PASS" else "❌"
        lines: List[str] = [
            f"## {status_icon} SpecGate OpenAPI Contract Gate — `{repo_name}` (PR #{int(pr_number)})",
            "",
            "| Metric | Value |",
            "| :--- | :--- |",
            f"| **Verdict** | `{verdict}` |",
            f"| **Recommended SemVer Bump** | `{semver_bump}` |",
            f"| **Breaking Changes** | `{breaking_count}` |",
            f"| **Additive / Non-Breaking Changes** | `{additive_count}` |",
            f"| **Cryptographic `audit_sha256`** | `{audit_sha256}` |",
            "",
            "### Breaking Change Analysis (`rule_id`, `severity`, `json_path`, `message`)",
            "",
            "| `rule_id` | `severity` | `json_path` | `message` |",
            "| :--- | :--- | :--- | :--- |",
        ]

        if breaking_changes:
            for item in breaking_changes:
                lines.append(
                    f"| `{item['rule_id']}` | `{item['severity']}` | `{item['json_path']}` | {item['message']} |"
                )
        else:
            lines.append("| `NONE` | `PASS` | `$` | Zero breaking changes detected. Contract is backward-compatible. |")

        lines.extend(
            [
                "",
                "---",
                (
                    "_SpecGate Deterministic Contract Engine • `audit_sha256`: "
                    f"`{audit_sha256}` • Upgrade to **SpecGate Team Plan** for signed "
                    "**SOC 2 Change Management Bundle** (CC8.1) & audit trail exports._"
                ),
            ]
        )
        return "\n".join(lines)

    def generate_semver_badge_svg(self, verdict: str, semver_bump: str) -> str:
        """Gera um badge SVG estilo shields.io exibindo SpecGate à esquerda e {verdict} | {semver_bump} à direita."""
        verdict_clean = (verdict or "PASS").strip()
        bump_clean = (semver_bump or "PATCH").strip()
        is_pass = verdict_clean.upper().startswith("PASS")
        right_color = "#10b981" if is_pass else "#ef4444"

        left_text = "SpecGate"
        right_text = f"{verdict_clean} | {bump_clean}"

        left_escaped = html.escape(left_text, quote=True)
        right_escaped = html.escape(right_text, quote=True)

        left_width = 68
        right_width = max(92, len(right_text) * 7 + 20)
        total_width = left_width + right_width
        left_center = left_width // 2
        right_center = left_width + (right_width // 2)

        return (
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{total_width}" height="20" '
            f'role="img" aria-label="{left_escaped}: {right_escaped}">'
            f"<title>{left_escaped}: {right_escaped}</title>"
            '<linearGradient id="sg-smooth" x2="0" y2="100%">'
            '<stop offset="0" stop-color="#bbb" stop-opacity=".1"/>'
            '<stop offset="1" stop-opacity=".1"/>'
            "</linearGradient>"
            f'<clipPath id="sg-round"><rect width="{total_width}" height="20" rx="3" fill="#fff"/></clipPath>'
            '<g clip-path="url(#sg-round)">'
            f'<rect width="{left_width}" height="20" fill="#1e293b"/>'
            f'<rect x="{left_width}" width="{right_width}" height="20" fill="{right_color}"/>'
            f'<rect width="{total_width}" height="20" fill="url(#sg-smooth)"/>'
            "</g>"
            '<g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" '
            'text-rendering="geometricPrecision" font-size="11">'
            f'<text x="{left_center}" y="14">{left_escaped}</text>'
            f'<text x="{right_center}" y="14">{right_escaped}</text>'
            "</g>"
            "</svg>"
        )

    def generate_soc2_audit_bundle(
        self,
        diff_result: Dict[str, Any],
        repo_name: str,
        pr_number: int,
        commit_sha: str = "HEAD",
    ) -> Dict[str, Any]:
        """Gera pacote JSON determinístico assinado por SHA-256 para conformidade SOC 2 CC8.1 (Change Management)."""
        norm = self._normalize_diff_result(diff_result)
        bundle_payload: Dict[str, Any] = {
            "schema_version": "1.0",
            "compliance_framework": "SOC 2 Type II",
            "trust_services_criteria": "CC8.1",
            "control_objective": "SOC 2 CC8.1 Change Management Authorization & Contract Integrity",
            "repo_name": str(repo_name),
            "pr_number": int(pr_number),
            "commit_sha": str(commit_sha),
            "verdict": norm["verdict"],
            "gate_passed": norm["gate_passed"],
            "recommended_semver_bump": norm["recommended_semver_bump"],
            "breaking_changes_count": norm["breaking_changes_count"],
            "additive_changes_count": norm["additive_changes_count"],
            "non_breaking_changes_count": norm["non_breaking_changes_count"],
            "breaking_changes": norm["breaking_changes"],
            "non_breaking_changes": norm["non_breaking_changes"],
            "audit_sha256": norm["audit_sha256"],
        }
        canonical_json = json.dumps(bundle_payload, sort_keys=True, separators=(",", ":"))
        bundle_integrity_sha256 = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()
        return {
            **bundle_payload,
            "bundle_integrity_sha256": bundle_integrity_sha256,
        }


def generate_pr_comment_markdown(
    diff_result: Dict[str, Any],
    repo_name: str = "org/repo",
    pr_number: int = 1,
) -> str:
    return SpecGateEngine().generate_pr_comment_markdown(
        diff_result=diff_result,
        repo_name=repo_name,
        pr_number=pr_number,
    )


def generate_semver_badge_svg(verdict: str, semver_bump: str) -> str:
    return SpecGateEngine().generate_semver_badge_svg(
        verdict=verdict,
        semver_bump=semver_bump,
    )


def generate_soc2_audit_bundle(
    diff_result: Dict[str, Any],
    repo_name: str,
    pr_number: int,
    commit_sha: str = "HEAD",
) -> Dict[str, Any]:
    return SpecGateEngine().generate_soc2_audit_bundle(
        diff_result=diff_result,
        repo_name=repo_name,
        pr_number=pr_number,
        commit_sha=commit_sha,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="SpecGate OpenAPI Breaking-Change Detector")
    parser.add_argument("base", help="Caminho para o arquivo JSON da especificação base")
    parser.add_argument("head", help="Caminho para o arquivo JSON da especificação proposta (PR)")
    args = parser.parse_args()

    with open(args.base, "r", encoding="utf-8") as f:
        base_spec = json.load(f)
    with open(args.head, "r", encoding="utf-8") as f:
        head_spec = json.load(f)

    engine = SpecGateEngine()
    report = engine.compare_specs(base_spec, head_spec)
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0 if report["gate_passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
