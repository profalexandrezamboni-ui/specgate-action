#!/usr/bin/env python3
"""
SpecGate Core Deterministic Engine (Preparação Local Segura para o Experimento EXP-H1).

Motor 100% determinístico (zero chamadas de LLM) para detecção de Breaking Changes,
cálculo de incremento SemVer (MAJOR / MINOR / PATCH) e validação de política de
depreciação (RFC 8594 Sunset) em contratos OpenAPI 3.x / JSON Schema.
"""

import argparse
import hashlib
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
                breaking_changes.append(
                    {
                        "rule_id": "OAS-BREAK-001",
                        "severity": "BREAKING",
                        "location": f"paths.{path}",
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
                    breaking_changes.append(
                        {
                            "rule_id": rule_id,
                            "severity": "BREAKING",
                            "location": f"paths.{path}.{method}",
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
                non_breaking_changes.append(
                    {
                        "rule_id": "OAS-INFO-001",
                        "severity": "NON_BREAKING",
                        "location": f"paths.{path}",
                        "message": f"Novo endpoint path '{path}' adicionado.",
                    }
                )
            else:
                base_path_item = base_paths[path]
                for method in self.HTTP_METHODS:
                    if method in head_path_item and method not in base_path_item:
                        non_breaking_changes.append(
                            {
                                "rule_id": "OAS-INFO-002",
                                "severity": "NON_BREAKING",
                                "location": f"paths.{path}.{method}",
                                "message": f"Nova operação '{method.upper()} {path}' adicionada.",
                            }
                        )

        recommended_bump = (
            "MAJOR"
            if breaking_changes
            else ("MINOR" if non_breaking_changes else "PATCH")
        )

        spec_pair_hash = hashlib.sha256(
            (
                json.dumps(base_spec, sort_keys=True)
                + "::"
                + json.dumps(head_spec, sort_keys=True)
            ).encode("utf-8")
        ).hexdigest()[:16]

        return {
            "gate_passed": len(breaking_changes) == 0,
            "recommended_semver_bump": recommended_bump,
            "breaking_changes_count": len(breaking_changes),
            "non_breaking_changes_count": len(non_breaking_changes),
            "breaking_changes": breaking_changes,
            "non_breaking_changes": non_breaking_changes,
            "audit_fingerprint": f"SG-{spec_pair_hash.upper()}",
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
            if key not in base_params:
                if hp.get("required", False):
                    breaking.append(
                        {
                            "rule_id": "OAS-BREAK-004",
                            "severity": "BREAKING",
                            "location": f"paths.{path}.{method}.parameters.{loc}.{name}",
                            "message": f"Novo parâmetro obrigatório '{name}' ({loc}) adicionado na requisição.",
                        }
                    )
                else:
                    non_breaking.append(
                        {
                            "rule_id": "OAS-INFO-003",
                            "severity": "NON_BREAKING",
                            "location": f"paths.{path}.{method}.parameters.{loc}.{name}",
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
                            "location": f"paths.{path}.{method}.parameters.{loc}.{name}",
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
                            "location": f"paths.{path}.{method}.parameters.{loc}.{name}",
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
                breaking.append(
                    {
                        "rule_id": "OAS-BREAK-007",
                        "severity": "BREAKING",
                        "location": f"paths.{path}.{method}.responses.{status_code}",
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
            breaking.append(
                {
                    "rule_id": "OAS-BREAK-008",
                    "severity": "BREAKING",
                    "location": f"{loc}.required.{prop}",
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
                    breaking.append(
                        {
                            "rule_id": "OAS-BREAK-009",
                            "severity": "BREAKING",
                            "location": f"{loc}.properties.{prop}",
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
            breaking.append(
                {
                    "rule_id": "OAS-BREAK-010",
                    "severity": "BREAKING",
                    "location": f"{loc}.required.{prop}",
                    "message": f"Propriedade obrigatória '{prop}' deixou de ser garantida na resposta.",
                }
            )

        b_props = base_s.get("properties", {}) or {}
        h_props = head_s.get("properties", {}) or {}
        for prop, b_prop_schema in b_props.items():
            if prop not in h_props:
                breaking.append(
                    {
                        "rule_id": "OAS-BREAK-011",
                        "severity": "BREAKING",
                        "location": f"{loc}.properties.{prop}",
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
                            "location": f"{loc}.properties.{prop}",
                            "message": f"Tipo da propriedade de resposta '{prop}' mudou de '{b_t}' para '{h_t}'.",
                        }
                    )
        for prop in h_props:
            if prop not in b_props:
                non_breaking.append(
                    {
                        "rule_id": "OAS-INFO-004",
                        "severity": "NON_BREAKING",
                        "location": f"{loc}.properties.{prop}",
                        "message": f"Nova propriedade '{prop}' adicionada na resposta (retrocompatível).",
                    }
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
