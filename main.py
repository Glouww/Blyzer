"""
main.py

Entry point for the artifact.
Parses a Solidity file into an AST, analyses it for access control and reentrancy vulnerabilities,
and reports the findings.
"""

import argparse
from core.parser import parseFile
from analyzers.access_control import findAccessControlIssues
from analyzers.reentrancy import findReentrancyIssues
from analyzers.unchecked_calls import findUncheckedExternalCalls
from core.reporter import printFindings

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Analyse a Solidity file for access control and reentrancy vulnerabilities."
    )
    parser.add_argument(
        "--file", "-f",
        type=str,
        required=True,
        help="Path to the Solidity (.sol) file to analyse."
    )
    args = parser.parse_args()

    try:
        ast = parseFile(args.file)
        
        # Collect findings from both analysers
        access_control_findings = findAccessControlIssues(ast)
        reentrancy_findings = findReentrancyIssues(ast)
        unchecked_calls_findings = findUncheckedExternalCalls(ast)
        
        # Combine findings
        all_findings = {
            "access_control": access_control_findings,
            "reentrancy": reentrancy_findings,
            "unchecked_calls": unchecked_calls_findings,
        }
        
        printFindings(all_findings)
    except ValueError as e:
        print(str(e))

if __name__ == "__main__":
    main()
