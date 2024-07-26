// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IAccount} from "./IAccount.sol";
import {IAccountExecute} from "./IAccountExecute.sol";
import {IERC7579Account} from "./IERC7579Account.sol";

interface IKernel is IAccount, IAccountExecute, IERC7579Account {
          
}
