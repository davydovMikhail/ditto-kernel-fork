// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IKernelFactory {

    function createAccount(bytes calldata data, bytes32 salt) external payable returns(address);

    function getAddress(bytes calldata data, bytes32 salt) external view returns(address);

    function implementation() external view returns(address);
}
