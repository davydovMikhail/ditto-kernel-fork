// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.23;

import { IDittoEntryPoint } from "../interfaces/IDittoEntryPoint.sol";
import { IDittoAdapter } from "../interfaces/IDittoAdapter.sol";


// Interface for the DittoEntryPoint DEP contract
contract DittoEntryPoint is IDittoEntryPoint {
    error UnregisteredWorkflow();

    Workflow[] historyWorkflow;
    IDittoAdapter adapter;
    mapping(uint256 => bool) private _registered;
    address private dittoOperator;

    constructor(address _dittoAdapter, address _dittoOperator) {
        adapter = IDittoAdapter(_dittoAdapter);
        adapter.init();
        dittoOperator = _dittoOperator;
    }

    modifier onlyOperator {
        if(msg.sender != dittoOperator) {
            revert OperatorUnauthorized();
        }
        _;
    }

    // Registers a workflow associated with a vault
    function registerWorkflow(uint256 workflowId) external onlyOperator {
        _registered[workflowId] = true;
    }

    // Executes a workflow
    function runWorkflow(address vaultAddress, uint256 workflowId) external {
        if(!_registered[workflowId]) {
            revert UnregisteredWorkflow();
        }
        adapter.executeFromDEP(vaultAddress, workflowId);
        historyWorkflow.push(
            Workflow(
                vaultAddress,
                workflowId
            )
        );
    }
    
    // Cancels a workflow and removes it from active workflows
    function cancelWorkflow(uint256 workflowId) external onlyOperator {
        _registered[workflowId] = false;
    }

    function isRegistered(uint256 workflowId) external view returns(bool) {
        return _registered[workflowId];
    }

    // Get a certain number of items from the history
    function getWorkflowSlice(uint _start, uint _end) external view returns(Workflow[] memory slice) {
        require(_end > _start, "Invalid input data");
        uint256 sliceLength = _end - _start;
        slice = new Workflow[](sliceLength);
        for(uint256 i = 0; i < sliceLength; i++) {
            uint256 sPosition = i + _start;
            slice[i] = historyWorkflow[sPosition];
        }
    }

    // Get the length of the history before requesting a slice
    function getWorkflowLength() external view returns(uint256) {
        return historyWorkflow.length;
    }
}