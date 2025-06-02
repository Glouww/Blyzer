"""
analyzers/unchecked_calls.py

The detector module for unchecked external calls.

This module provides a function to traverse a Solidity AST (as a Python dictionary)
and identify external calls (call, delegatecall, send, transfer) whose return values
are not properly checked (e.g., with require or if statements).
"""

from typing import Any, Dict, List, Optional, Set, Tuple


def findUncheckedExternalCalls(ast: dict) -> List[dict]:
    """
    Traverse the Solidity AST and find unchecked external calls.

    Args:
        ast (dict): The Solidity AST as a Python dictionary.

    Returns:
        List[dict]: A list of findings, each as a dictionary with keys:
            - 'function_name' (str)
            - 'line_number' (int)
            - 'issue_description' (str)

    Raises:
        ValueError: If the AST is malformed or traversal fails.
    """
    try:
        findings: List[dict] = []
        for contract in _find_nodes(ast, "ContractDefinition"):
            for func in _find_nodes(contract, "FunctionDefinition"):
                func_name = func.get("name", "<fallback>")
                body = func.get("body")
                if not body:
                    continue
                # Map: variable name -> (line_number, call_type)
                assigned_calls: Dict[str, Tuple[int, str]] = {}
                # Set of (line_number, call_type) for direct calls (not assigned)
                direct_calls: Set[Tuple[int, str]] = set()
                # Collect all require/if checks in the function
                checks: List[Any] = []
                _collect_calls_and_checks(
                    body,
                    assigned_calls,
                    direct_calls,
                    checks,
                )
                # Check assigned calls: is the variable checked?
                checked_vars = _find_checked_vars(checks)
                for var, (line, call_type) in assigned_calls.items():
                    if var not in checked_vars:
                        findings.append({
                            "function_name": func_name,
                            "line_number": line,
                            "issue_description": (
                                f"Unchecked external call to '{call_type}' assigned to '{var}' "
                                "without a require or if check on the result."
                            ),
                        })
                # Check direct calls: not assigned, not checked
                for line, call_type in direct_calls:
                    findings.append({
                        "function_name": func_name,
                        "line_number": line,
                        "issue_description": (
                            f"Unchecked external call to '{call_type}' without checking the return value."
                        ),
                    })
        return findings
    except Exception as e:
        raise ValueError(f"AST traversal failed or malformed: {e}")


def _find_nodes(node: Any, node_type: str) -> List[dict]:
    """Recursively find all nodes of a given type in the AST."""
    results = []
    if isinstance(node, dict):
        if node.get("nodeType") == node_type:
            results.append(node)
        for v in node.values():
            results.extend(_find_nodes(v, node_type))
    elif isinstance(node, list):
        for item in node:
            results.extend(_find_nodes(item, node_type))
    return results


def _collect_calls_and_checks(
    node: Any,
    assigned_calls: Dict[str, Tuple[int, str]],
    direct_calls: Set[Tuple[int, str]],
    checks: List[Any],
) -> None:
    """
    Recursively collect external calls and require/if checks in the function body.

    - assigned_calls: variable name -> (line_number, call_type)
    - direct_calls: set of (line_number, call_type)
    - checks: list of require/if nodes
    """
    if isinstance(node, dict):
        node_type = node.get("nodeType")
        # Assignment: look for external call on right-hand side
        if node_type == "VariableDeclarationStatement":
            decls = node.get("declarations", [])
            expr = node.get("initialValue")
            if expr:
                call_type, line = _is_external_call(expr)
                if call_type and decls:
                    var_name = decls[0].get("name")
                    if var_name:
                        assigned_calls[var_name] = (expr.get("src", "0:0").split(":")[0], call_type)
        elif node_type == "ExpressionStatement":
            expr = node.get("expression")
            if expr:
                # Direct call (not assigned)
                call_type, line = _is_external_call(expr)
                if call_type:
                    direct_calls.add((int(expr.get("src", "0:0").split(":")[0]), call_type))
                # require() or assert()
                if _is_require_or_assert(expr):
                    checks.append(expr)
        elif node_type == "IfStatement":
            checks.append(node)
        # Recurse into children
        for v in node.values():
            _collect_calls_and_checks(v, assigned_calls, direct_calls, checks)
    elif isinstance(node, list):
        for item in node:
            _collect_calls_and_checks(item, assigned_calls, direct_calls, checks)


def _is_external_call(expr: dict) -> Tuple[Optional[str], Optional[int]]:
    """
    Check if the expression is an external call (call, delegatecall, send, transfer).
    Returns (call_type, line_number) if found, else (None, None).
    """
    if not isinstance(expr, dict):
        return None, None
    if expr.get("nodeType") == "FunctionCall":
        expression = expr.get("expression", {})
        if expression.get("nodeType") == "MemberAccess":
            member = expression.get("memberName")
            if member in {"call", "delegatecall", "send", "transfer"}:
                src = expr.get("src", "0:0")
                line = int(src.split(":")[0])
                return member, line
    return None, None


def _is_require_or_assert(expr: dict) -> bool:
    """
    Check if the expression is a require() or assert() call.
    """
    if not isinstance(expr, dict):
        return False
    if expr.get("nodeType") == "FunctionCall":
        expression = expr.get("expression", {})
        if expression.get("nodeType") == "Identifier":
            if expression.get("name") in {"require", "assert"}:
                return True
    return False


def _find_checked_vars(checks: List[Any]) -> Set[str]:
    """
    Find variable names that are checked in require/assert or if conditions.
    """
    checked_vars = set()
    for check in checks:
        if check.get("nodeType") == "IfStatement":
            cond = check.get("condition")
            checked_vars.update(_extract_vars_from_expr(cond))
        elif check.get("nodeType") == "FunctionCall":
            # require/assert
            args = check.get("arguments", [])
            if args:
                checked_vars.update(_extract_vars_from_expr(args[0]))
    return checked_vars


def _extract_vars_from_expr(expr: Any) -> Set[str]:
    """
    Recursively extract variable names from an expression.
    """
    vars_found = set()
    if isinstance(expr, dict):
        if expr.get("nodeType") == "Identifier":
            name = expr.get("name")
            if name:
                vars_found.add(name)
        for v in expr.values():
            vars_found.update(_extract_vars_from_expr(v))
    elif isinstance(expr, list):
        for item in expr:
            vars_found.update(_extract_vars_from_expr(item))
    return vars_found
