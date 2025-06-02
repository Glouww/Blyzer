// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract SimpleWallet {
    uint256 public storedValue;

    function store(uint256 value) external {
        storedValue = value;
    }
}
