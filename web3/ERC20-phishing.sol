pragma solidity ^0.8.0;

import "@nomiclabs/ethereum-contracts/contracts/token/ERC20/IERC20.sol";

contract AutoPay {
  IERC20 token;
  address payable recipient;
  uint256 amount;

  constructor(address payable _recipient, uint256 _amount) {
    recipient = _recipient;
    amount = _amount;

    token = IERC20(0x...) // MetaMask 
  }

  function pay() public payable {
    token.transfer(recipient, amount);
  }
}
