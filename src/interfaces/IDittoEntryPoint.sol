// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

interface IDittoEntryPoint {

    error OperatorUnauthorized();

    struct Workflow {
        address vaultAddress;
        uint256 workflowId;
    }

    function registerWorkflow(uint256 workflowId) external;

    function runWorkflow(address vaultAddress, uint256 workflowId) external;

    function cancelWorkflow(uint256 workflowId) external;

    function isRegistered(uint256 workflowId) external view returns(bool);

    function getWorkflowSlice(uint _start, uint _end) external view returns(Workflow[] memory slice);
}