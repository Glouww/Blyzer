// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract ReentrancyVulnerable {
    mapping(address => uint) public balances;

    // Deposit function allows users to deposit Ether into the contract
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    // Withdraw function is vulnerable to reentrancy attack
    function withdraw(uint _amount) public {
        require(balances[msg.sender] >= _amount, "Insufficient balance");

        // First transfer the Ether, then update the balance
        payable(msg.sender).transfer(_amount);
        balances[msg.sender] -= _amount;
    }
}
