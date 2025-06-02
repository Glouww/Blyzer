"""
analyzers/reentrancy.py

The detector module for reentrancy vulnerabilities.
"""

from typing import Any, List, Set


def findReentrancyIssues(ast: dict) -> list[dict]:
    """
    Analyses a Solidity contract AST to find reentrancy vulnerabilities.
    
    Args:
        ast: The Abstract Syntax Tree of a Solidity contract as a Python dictionary.
        
    Returns:
        A list of dictionaries containing information about detected reentrancy issues.
        Each dictionary contains:
            - function_name: The name of the function with the vulnerability
            - line_number: The line number where the vulnerability was detected
            - issue_description: A description of the vulnerability
            
    Errors:
        ValueError: If the AST is malformed or traversal fails.
    """
    if not isinstance(ast, dict):
        raise ValueError("Invalid AST format: expected a dictionary")
    
    # Handle different AST formats
    # Some tools wrap the AST in a dictionary with an 'ast' key
    # While others provide the AST directly
    ast_to_analyze = ast
    if "ast" in ast:
        ast_to_analyze = ast["ast"]
    
    findings = []
    
    # Traverse the AST to find all function definitions
    for node in _walk_ast(ast_to_analyze):
        if node.get("nodeType") == "FunctionDefinition":
            function_name = node.get("name", "Unknown")
            
            # Flatten all statements in the function body
            statements = _flatten_statements(node)
            
            # Track state variables read before external calls
            state_vars_read_before_call = set()
            
            # Track external calls and state modifications
            external_calls = []
            state_modifications = []
            
            # First stage: identify all external calls and state modifications
            for i, stmt in enumerate(statements):
                if _is_external_call(stmt):
                    external_calls.append(stmt)
                elif _is_state_modifying(stmt):
                    state_modifications.append(stmt)
            
            # If there are no external calls, no need to check for reentrancy
            if not external_calls:
                continue
                
            # Second stage: check for reentrancy patterns
            for i, stmt in enumerate(statements):
                # Check for state variable reads before external calls
                if _is_external_call(stmt):
                    # Check if any state variables were read before this call
                    for prev_stmt in statements[:i]:
                        state_vars_read_before_call.update(_get_state_vars_read(prev_stmt))
                    
                    # Check if any of these read state variables are modified after the call
                    for next_stmt in statements[i+1:]:
                        if _is_state_modifying(next_stmt):
                            modified_vars = _get_state_vars_modified(next_stmt)
                            
                            if state_vars_read_before_call.intersection(modified_vars):
                                line_number = _get_line_number(stmt)
                                findings.append({
                                    "function_name": function_name,
                                    "line_number": line_number,
                                    "issue_description": (
                                        f"Potential reentrancy vulnerability: State variables "
                                        f"{state_vars_read_before_call.intersection(modified_vars)} "
                                        f"are read before an external call and modified after it."
                                    )
                                })
                                break
                
                # Check for state modifications after external calls
                elif _is_state_modifying(stmt):
                    # Check if there was an external call before this state modification
                    for prev_stmt in statements[:i]:
                        if _is_external_call(prev_stmt):
                            line_number = _get_line_number(stmt)
                            findings.append({
                                "function_name": function_name,
                                "line_number": line_number,
                                "issue_description": (
                                    f"Potential reentrancy vulnerability: State modification "
                                    f"occurs after an external call."
                                )
                            })
                            break
            
            # Third stage: additional check for reentrancy patterns (marks potential issues).
            if external_calls and state_modifications and not findings:
                # Check if any external call comes before any state modification
                for ext_call in external_calls:
                    ext_call_idx = statements.index(ext_call)
                    for state_mod in state_modifications:
                        state_mod_idx = statements.index(state_mod)
                        if state_mod_idx > ext_call_idx:
                            line_number = _get_line_number(ext_call)
                            findings.append({
                                "function_name": function_name,
                                "line_number": line_number,
                                "issue_description": (
                                    f"Potential reentrancy vulnerability: Function contains "
                                    f"external calls followed by state modifications."
                                )
                            })
                            break
                    if findings:
                        break
    
    return findings


def _walk_ast(node: Any) -> List[dict]:
    """
    Recursively walk the AST to find all nodes.
    
    Args:
        node: A node in the AST.
        
    Returns:
        A list of all nodes in the AST.
    """
    if not isinstance(node, dict):
        return []
    
    result = [node]
    
    # Recursively process children
    for key, value in node.items():
        if isinstance(value, dict):
            result.extend(_walk_ast(value))
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    result.extend(_walk_ast(item))
    
    return result


def _flatten_statements(node: dict) -> List[dict]:
    """
    Flatten all executable statements inside function bodies.
    
    Args:
        node: A function definition node.
        
    Returns:
        A list of all executable statements in the function body.
    """
    if not isinstance(node, dict) or node.get("nodeType") != "FunctionDefinition":
        return []
    
    body = node.get("body", {})
    if not isinstance(body, dict) or body.get("nodeType") != "Block":
        return []
    
    statements = body.get("statements", [])
    flattened = []
    
    for stmt in statements:
        flattened.extend(_flatten_statement(stmt))
    
    return flattened


def _flatten_statement(node: dict) -> List[dict]:
    """
    Flatten a single statement, handling nested structures.
    
    Args:
        node: A statement node.
        
    Returns:
        A list of flattened statements.
    """
    if not isinstance(node, dict):
        return []
    
    node_type = node.get("nodeType")
    
    # Base case: simple statements
    if node_type in ["ExpressionStatement", "Assignment", "VariableDeclarationStatement"]:
        return [node]
    
    # Handle if statements
    if node_type == "IfStatement":
        result = []
        if "trueBody" in node and isinstance(node["trueBody"], dict):
            if node["trueBody"].get("nodeType") == "Block":
                for stmt in node["trueBody"].get("statements", []):
                    result.extend(_flatten_statement(stmt))
            else:
                result.extend(_flatten_statement(node["trueBody"]))
        
        if "falseBody" in node and isinstance(node["falseBody"], dict):
            if node["falseBody"].get("nodeType") == "Block":
                for stmt in node["falseBody"].get("statements", []):
                    result.extend(_flatten_statement(stmt))
            else:
                result.extend(_flatten_statement(node["falseBody"]))
        
        return result
    
    # Handle for loops
    if node_type == "ForStatement":
        result = []
        if "body" in node and isinstance(node["body"], dict):
            if node["body"].get("nodeType") == "Block":
                for stmt in node["body"].get("statements", []):
                    result.extend(_flatten_statement(stmt))
            else:
                result.extend(_flatten_statement(node["body"]))
        return result
    
    # Handle while loops
    if node_type == "WhileStatement":
        result = []
        if "body" in node and isinstance(node["body"], dict):
            if node["body"].get("nodeType") == "Block":
                for stmt in node["body"].get("statements", []):
                    result.extend(_flatten_statement(stmt))
            else:
                result.extend(_flatten_statement(node["body"]))
        return result
    
    # Handle do-while loops
    if node_type == "DoWhileStatement":
        result = []
        if "body" in node and isinstance(node["body"], dict):
            if node["body"].get("nodeType") == "Block":
                for stmt in node["body"].get("statements", []):
                    result.extend(_flatten_statement(stmt))
            else:
                result.extend(_flatten_statement(node["body"]))
        return result
    
    # Handle blocks
    if node_type == "Block":
        result = []
        for stmt in node.get("statements", []):
            result.extend(_flatten_statement(stmt))
        return result
    
    # Default case: return the node itself
    return [node]


def _is_external_call(stmt: dict) -> bool:
    """
    Detect external calls, including those in assignments.
    
    Args:
        stmt: A statement node.
        
    Returns:
        True if the statement contains an external call, False otherwise.
    """
    if not isinstance(stmt, dict):
        return False
    
    node_type = stmt.get("nodeType")
    
    # Check for direct external calls
    if node_type == "ExpressionStatement":
        expr = stmt.get("expression", {})
        if expr.get("nodeType") == "FunctionCall":
            func = expr.get("expression", {})
            if func.get("nodeType") == "MemberAccess":
                member_name = func.get("memberName", "")
                if member_name in ["call", "delegatecall", "send", "transfer"]:
                    return True
            # Check for direct call to address
            elif func.get("nodeType") == "Identifier":
                # This is a direct call to an address
                return True
    
    # Check for external calls in assignments
    if node_type == "Assignment":
        right_side = stmt.get("rightHandSide", {})
        if right_side.get("nodeType") == "FunctionCall":
            func = right_side.get("expression", {})
            if func.get("nodeType") == "MemberAccess":
                member_name = func.get("memberName", "")
                if member_name in ["call", "delegatecall", "send", "transfer"]:
                    return True
            # Check for direct call to address
            elif func.get("nodeType") == "Identifier":
                # This is a direct call to an address
                return True
    
    # Check for external calls in variable declarations
    if node_type == "VariableDeclarationStatement":
        declarations = stmt.get("declarations", [])
        for var in declarations:
            if var is None:
                continue
            if var.get("nodeType") == "VariableDeclaration":
                initial_value = var.get("initialValue", {})
                if initial_value.get("nodeType") == "FunctionCall":
                    func = initial_value.get("expression", {})
                    if func.get("nodeType") == "MemberAccess":
                        member_name = func.get("memberName", "")
                        if member_name in ["call", "delegatecall", "send", "transfer"]:
                            return True
                    # Check for direct call to address
                    elif func.get("nodeType") == "Identifier":
                        # This is a direct call to an address
                        return True
    
    return False


def _is_state_modifying(stmt: dict) -> bool:
    """
    Detect assignments to state variables.
    
    Args:
        stmt: A statement node.
        
    Returns:
        True if the statement modifies a state variable, False otherwise.
    """
    if not isinstance(stmt, dict):
        return False
    
    node_type = stmt.get("nodeType")
    
    # Check for assignments
    if node_type == "Assignment":
        left_side = stmt.get("leftHandSide", {})
        return _is_state_variable(left_side)
    
    # Check for ExpressionStatement with Assignment
    if node_type == "ExpressionStatement":
        expr = stmt.get("expression", {})
        if expr.get("nodeType") == "Assignment":
            left_side = expr.get("leftHandSide", {})
            return _is_state_variable(left_side)
    
    # Check for variable declarations with initializers
    if node_type == "VariableDeclarationStatement":
        declarations = stmt.get("declarations", [])
        for var in declarations:
            if var is None:
                continue
            if var.get("nodeType") == "VariableDeclaration":
                # Check if it's a state variable
                if var.get("stateVariable", False):
                    return True
    
    # Check for ExpressionStatement that might be modifying state
    if node_type == "ExpressionStatement":
        expr = stmt.get("expression", {})
        if expr.get("nodeType") == "FunctionCall":
            # Check if it's a call to a function that might modify state
            func = expr.get("expression", {})
            if func.get("nodeType") == "MemberAccess":
                # This could be a state-modifying function call
                return True
    
    return False


def _is_state_variable(node: dict) -> bool:
    """
    Check if a node represents a state variable.
    
    Args:
        node: A node in the AST.
        
    Returns:
        True if the node represents a state variable, False otherwise.
    """
    if not isinstance(node, dict):
        return False
    
    node_type = node.get("nodeType")
    
    # Direct identifier (state variable)
    if node_type == "Identifier":
        return True
    
    # Member access (e.g., this.balance)
    if node_type == "MemberAccess":
        return True
    
    # Index access (e.g., balances[addr])
    if node_type == "IndexAccess":
        return True
    
    return False


def _get_state_vars_read(stmt: dict) -> Set[str]:
    """
    Identify state variables read in a statement.
    
    Args:
        stmt: A statement node.
        
    Returns:
        A set of state variable names read in the statement.
    """
    if not isinstance(stmt, dict):
        return set()
    
    result = set()
    
    # For assignments, check the right-hand side
    if stmt.get("nodeType") == "Assignment":
        right_side = stmt.get("rightHandSide", {})
        result.update(_extract_state_vars(right_side))
    
    # For function calls, check the arguments
    elif stmt.get("nodeType") == "ExpressionStatement":
        expr = stmt.get("expression", {})
        if expr.get("nodeType") == "FunctionCall":
            for arg in expr.get("arguments", []):
                result.update(_extract_state_vars(arg))
    
    # For variable declarations, check the initializer
    elif stmt.get("nodeType") == "VariableDeclarationStatement":
        declarations = stmt.get("declarations", [])
        for var in declarations:
            if var is None:
                continue
            if var.get("nodeType") == "VariableDeclaration":
                initial_value = var.get("initialValue", {})
                result.update(_extract_state_vars(initial_value))
    
    return result


def _get_state_vars_modified(stmt: dict) -> Set[str]:
    """
    Identify state variables modified in a statement.
    
    Args:
        stmt: A statement node.
        
    Returns:
        A set of state variable names modified in the statement.
    """
    if not isinstance(stmt, dict):
        return set()
    
    result = set()
    
    # For assignments, check the left-hand side
    if stmt.get("nodeType") == "Assignment":
        left_side = stmt.get("leftHandSide", {})
        if _is_state_variable(left_side):
            result.add(_get_variable_name(left_side))
    
    # For ExpressionStatement with Assignment
    elif stmt.get("nodeType") == "ExpressionStatement":
        expr = stmt.get("expression", {})
        if expr.get("nodeType") == "Assignment":
            left_side = expr.get("leftHandSide", {})
            if _is_state_variable(left_side):
                result.add(_get_variable_name(left_side))
    
    # For variable declarations, check if it's a state variable
    elif stmt.get("nodeType") == "VariableDeclarationStatement":
        declarations = stmt.get("declarations", [])
        for var in declarations:
            if var is None:
                continue
            if var.get("nodeType") == "VariableDeclaration":
                if var.get("stateVariable", False):
                    result.add(var.get("name", ""))
    
    # For ExpressionStatement that might be modifying state
    elif stmt.get("nodeType") == "ExpressionStatement":
        expr = stmt.get("expression", {})
        if expr.get("nodeType") == "FunctionCall":
            # Check if it's a call to a function that might modify state
            func = expr.get("expression", {})
            if func.get("nodeType") == "MemberAccess":
                # This could be a state-modifying function call
                # Try to extract the state variable name
                base = func.get("expression", {})
                if base.get("nodeType") == "Identifier":
                    result.add(base.get("name", ""))
    
    return result


def _extract_state_vars(node: dict) -> Set[str]:
    """
    Extract state variable names from a node.
    
    Args:
        node: A node in the AST.
        
    Returns:
        A set of state variable names.
    """
    if not isinstance(node, dict):
        return set()
    
    result = set()
    
    # Direct identifier
    if node.get("nodeType") == "Identifier":
        result.add(node.get("name", ""))
    
    # Member access
    elif node.get("nodeType") == "MemberAccess":
        result.add(_get_variable_name(node))
    
    # Index access
    elif node.get("nodeType") == "IndexAccess":
        result.add(_get_variable_name(node))
    
    # Recursively check children
    for key, value in node.items():
        if isinstance(value, dict):
            result.update(_extract_state_vars(value))
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    result.update(_extract_state_vars(item))
    
    return result


def _get_variable_name(node: dict) -> str:
    """
    Extract the variable name from a node.
    
    Args:
        node: A node in the AST.
        
    Returns:
        The variable name as a string.
    """
    if not isinstance(node, dict):
        return ""
    
    node_type = node.get("nodeType")
    
    # Direct identifier
    if node_type == "Identifier":
        return node.get("name", "")
    
    # Member access
    elif node_type == "MemberAccess":
        expr = node.get("expression", {})
        if expr.get("nodeType") == "Identifier":
            return expr.get("name", "")
        elif expr.get("nodeType") == "MemberAccess":
            return _get_variable_name(expr)
    
    # Index access
    elif node_type == "IndexAccess":
        base = node.get("base", {})
        if base.get("nodeType") == "Identifier":
            return base.get("name", "")
        elif base.get("nodeType") == "MemberAccess":
            return _get_variable_name(base)
    
    return ""


def _get_line_number(node: dict) -> int:
    """
    Extract line number from node if available.
    
    Args:
        node: A node in the AST.
        
    Returns:
        The line number, or 0 if not available.
    """
    if not isinstance(node, dict):
        return 0
    
    # Try to get the line number from the node
    if "src" in node:
        src_parts = node["src"].split(":")
        if len(src_parts) >= 2:
            try:
                return int(src_parts[0])
            except ValueError:
                pass
    
    # Try to get the line number from the location
    if "loc" in node and isinstance(node["loc"], dict):
        if "start" in node["loc"] and isinstance(node["loc"]["start"], dict):
            if "line" in node["loc"]["start"]:
                return node["loc"]["start"]["line"]
    
    return 0