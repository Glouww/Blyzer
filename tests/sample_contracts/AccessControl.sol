// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract VulnerableContract {
    address public owner;

    function changeOwner(address _newOwner) public {
        owner = _newOwner;
    }

    function withdraw() external {
        payable(msg.sender).transfer(address(this).balance);
    }

    function safeFunction() public view returns (uint) {
        return address(this).balance;
    }
}
