// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract ReentrancyTest {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() public {
        uint256 bal = balances[msg.sender];
        require(bal > 0, "No balance to withdraw");

        (bool success, ) = msg.sender.call{value: bal}("");
        require(success, "Transfer failed");

        balances[msg.sender] = 0;
    }

    function safeWithdraw() public {
        uint256 bal = balances[msg.sender];
        require(bal > 0, "No balance to withdraw");

        balances[msg.sender] = 0;

        (bool success, ) = msg.sender.call{value: bal}("");
        require(success, "Transfer failed");
    }
}
