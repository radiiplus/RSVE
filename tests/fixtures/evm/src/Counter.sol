pragma solidity ^0.8.20;

contract Counter {
    uint256 public count;

    event Mutation(uint256 beforeCount, uint256 afterCount, string canary);

    function increment(uint256 amount, string calldata canary) external {
        require(amount > 0 && amount <= 10, "guard");
        uint256 beforeCount = count;
        count += amount;
        emit Mutation(beforeCount, count, canary);
    }
}
