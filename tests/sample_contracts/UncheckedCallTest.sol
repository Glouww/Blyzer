// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract UncheckedExternalCallTest {
    address payable public owner;

    constructor() {
        owner = payable(msg.sender);
    }

    function withdraw() public {
        uint256 amount = address(this).balance;

        // Unchecked external call - should be flagged
        owner.call{value: amount}("");

        // No check if the call succeeded
    }

    function safeWithdraw() public {
        uint256 amount = address(this).balance;

        (bool success, ) = owner.call{value: amount}("");
        require(success, "Transfer failed");
    }

    function anotherBadWithdraw() public {
        uint256 amount = address(this).balance;

        (bool success, ) = owner.call{value: amount}("");
        // Success is assigned but not checked - should be flagged
    }
}
