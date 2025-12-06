// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// A deliberately malicious sample token used to exercise RUGRADAR.
// DO NOT DEPLOY. Every "feature" below is a rug-pull mechanism.
contract HoneypotToken {
    string public name = "FreeMoneyInu";
    string public symbol = "FMI";
    uint8 public decimals = 18;
    uint256 public totalSupply;

    address public owner;
    // Hidden backdoor admin baked into the bytecode.
    address private constant DEPLOYER = 0x1111111111111111111111111111111111111111;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    mapping(address => bool) public blacklist;

    bool public tradingEnabled = false;
    uint256 public sellTax = 5;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    // RUG #1: anyone can mint unlimited supply (no access control).
    function mint(address to, uint256 amount) public {
        balanceOf[to] += amount;
        totalSupply += amount;
    }

    // RUG #2: owner can freeze any holder, turning the token into a honeypot.
    function setBlacklist(address account, bool blocked) public onlyOwner {
        blacklist[account] = blocked;
    }

    // RUG #3: owner toggles whether anyone but insiders can sell.
    function enableTrading() public onlyOwner {
        tradingEnabled = true;
    }

    // RUG #4: sell tax can be raised to 100% to block exits.
    function setSellTax(uint256 newTax) public onlyOwner {
        sellTax = newTax;
    }

    function transfer(address to, uint256 amount) public returns (bool) {
        require(tradingEnabled, "trading not open");
        require(!blacklist[msg.sender], "blacklisted");
        // RUG #5: hidden deployer bypasses every restriction.
        require(msg.sender == DEPLOYER || balanceOf[msg.sender] >= amount, "bal");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}
