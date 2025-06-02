
"""
core/parser.py

The module responsible for parsing Solidity code into ASTs.
"""

from typing import Dict
from solcx import compile_standard, install_solc, set_solc_version
from solcx.exceptions import SolcError

def parseFile(filepath: str) -> Dict:
    """
    Parses a Solidity source file and returns its AST using py-solc-x.

    Args:
        filepath (str): Path to the Solidity (.sol) file.

    Returns:
        dict: The AST of the Solidity file.

    Errors:
        ValueError: If parsing or compilation fails.
    """
    solc_version = "0.8.29"
    try:
        set_solc_version(solc_version)
    except Exception:
        install_solc(solc_version)
        set_solc_version(solc_version)

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            source = f.read()
        compiled = compile_standard(
            {
                "language": "Solidity",
                "sources": {filepath: {"content": source}},
                "settings": {
                    "outputSelection": {
                        "*": {
                            "": ["ast"]
                        }
                    }
                },
            },
            allow_paths=".",
        )
        sources = compiled.get("sources", {})
        ast = None
        for key, value in sources.items():
            if "ast" in value:
                ast = value["ast"]
                break
        if ast is None:
            raise ValueError(
                f"Failed to parse Solidity file: AST not found in compiler output. Source keys: {list(sources.keys())}, value keys: {list(value.keys()) if 'value' in locals() else 'N/A'}"
            )
        return ast
    except (SolcError, KeyError, Exception) as error:
        raise ValueError(f"Failed to parse Solidity file: {error}")