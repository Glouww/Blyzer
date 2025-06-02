João Bizarro, 2025

# Blyzer - Solidity Static Analysis Tool

Blyzer is a proof-of-concept static analysis tool designed to detect security vulnerabilities in Solidity smart contracts. It performs automated analysis to identify issues such as access control vulnerabilities, reentrancy attacks, and unchecked external calls.

## Features

- **Access Control Analysis**: Identifies potential access control vulnerabilities in smart contracts
- **Reentrancy Detection**: Analyzes contracts for potential reentrancy attack vectors
- **Unchecked External Calls**: Detects unchecked external calls that could lead to security issues
- **AST-based Analysis**: Utilizes Abstract Syntax Tree parsing for accurate code analysis
- **Comprehensive Reporting**: Provides detailed findings with clear explanations

## Usage

On a command prompt, Run the analyser on a Solidity file using the following command:

```bash
python main.py --file path/to/your/contract.sol
```

or using the short form:

```bash
python main.py -f path/to/your/contract.sol
```
Note: this command should be ran in the 'Blyzer' folder (C:\path\to\Blyzer)

## Project Structure

```
blyzer/
├── analyzers/        # Analysis modules for different vulnerability types
├── core/             # Core functionality including parser and reporter
├── tests/            # Test suite
├── main.py           # Entry point
└── README.md         # This file
```

