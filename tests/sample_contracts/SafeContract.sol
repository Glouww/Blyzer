// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract SimpleWallet {

    // Mapping to keep track of user balances
    mapping(address => uint256) public balances;

    // Event to emit when a deposit is made
    event Deposit(address indexed user, uint256 amount);

    // Event to emit when a withdrawal is made
    event Withdrawal(address indexed user, uint256 amount);

    // Deposit function to add Ether to the user's balance
    function deposit() external payable {
        require(msg.value > 0, "You must send some Ether");

        // Add the deposited Ether to the user's balance
        balances[msg.sender] += msg.value;

        // Emit the deposit event
        emit Deposit(msg.sender, msg.value);
    }

    // Withdraw function to allow users to withdraw their Ether
    function withdraw(uint256 amount) external {
        require(amount > 0, "Amount must be greater than zero");
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // Subtract the amount from the user's balance
        balances[msg.sender] -= amount;

        // Transfer the amount to the user
        payable(msg.sender).transfer(amount);

        // Emit the withdrawal event
        emit Withdrawal(msg.sender, amount);
    }

    // Function to check the balance of the contract (total Ether in the contract)
    function contractBalance() external view returns (uint256) {
        return address(this).balance;
    }
}
