"""
analyzers/access_control.py

The detector module for access control vulnerabilities.
The main function, findAccessControlIssues, traverses the AST to identify public or external functions
that modify state without proper access control measures.
"""

from typing import Any, Dict, List

def findAccessControlIssues(ast: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Traverses the Solidity AST to find public or external functions that modify state
    without access control (require/assert statements or modifiers).

    Args:
        ast (dict): The Solidity contract AST.

    Returns:
        list[dict]: List of detected access control issues.

    Errors:
        ValueError: If the AST is malformed or traversal fails.
    """
    issues = []

    def is_state_modifying(node: Dict[str, Any]) -> bool:
        # Detects state-modifying operations: assignments, emits, and calls
        if node.get("nodeType") == "Assignment":
            return True
        if node.get("nodeType") == "EmitStatement":
            return True
        if node.get("nodeType") == "FunctionCall":
            expression = node.get("expression", {})
            if expression.get("nodeType") == "Identifier":
                if expression.get("name") in {"transfer", "send", "call", "delegatecall", "selfdestruct"}:
                    return True
        return False

    def has_access_control(node: Dict[str, Any]) -> bool:
        # Checks for require/assert or modifiers
        if node.get("modifiers"):
            return True
        if "body" in node and node["body"]:
            statements = node["body"].get("statements", [])
            for stmt in statements:
                if stmt.get("nodeType") == "ExpressionStatement":
                    expr = stmt.get("expression", {})
                    if expr.get("nodeType") == "FunctionCall":
                        callee = expr.get("expression", {})
                        if callee.get("nodeType") == "Identifier" and callee.get("name") in {"require", "assert"}:
                            return True
        return False

    def traverse(node: Dict[str, Any]):
        if not isinstance(node, dict):
            return
        if node.get("nodeType") == "FunctionDefinition":
            visibility = node.get("visibility")
            if visibility in {"public", "external"} and not node.get("stateMutability") in {"view", "pure"}:
                state_modifying = False
                if "body" in node and node["body"]:
                    # Recursively check for state-modifying operations in the function body
                    nodes_to_check = [node["body"]]
                    while nodes_to_check:
                        current = nodes_to_check.pop()
                        if isinstance(current, dict):
                            if is_state_modifying(current):
                                state_modifying = True
                            nodes_to_check.extend(
                                v for v in current.values() if isinstance(v, (dict, list))
                            )
                        elif isinstance(current, list):
                            nodes_to_check.extend(current)
                if state_modifying and not has_access_control(node):
                    issues.append({
                        "function_name": node.get("name", "<unknown>"),
                        "line_number": node.get("src", "0:0:0").split(":")[0] if "src" in node else -1,
                        "issue_description": "Public or external function modifies state without access control."
                    })
        # Traverse children
        for key, value in node.items():
            if isinstance(value, dict):
                traverse(value)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        traverse(item)

    try:
        traverse(ast)
    except Exception as e:
        raise ValueError(f"Failed to traverse AST: {e}")

    return issues
