// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { IERC7579Account } from "../interfaces/IERC7579Account.sol";
import { Execution } from "../types/Structs.sol";
import { IDittoAdapter } from "../interfaces/IDittoAdapter.sol";
import { ExecLib } from "../utils/ExecLib.sol";

contract DittoAdapter is IDittoAdapter {
    
    bytes32 private constant ENTRY_POINT_LOGIC_STORAGE_POSITION =
        keccak256("dittoadapter.storage");

    function _getLocalStorage()
        internal
        pure
        returns (EntryPointStorage storage eps)
    {
        bytes32 position = ENTRY_POINT_LOGIC_STORAGE_POSITION;
        assembly ("memory-safe") {
            eps.slot := position
        }
    }

    function init() external {
        require(_getLocalStorage().dep == address(0), "Already init");
        _getLocalStorage().dep = msg.sender; 
    }

    function addWorkflow(
        Execution[] memory _execution,
        uint256 _count
    ) external {
        EntryPointStorage storage eps = _getLocalStorage();

        uint256 workflowKey;
        unchecked {
            workflowKey = eps.workflowIds++;
        }

        WorkflowScenario storage newWorkflow = eps.workflows[workflowKey];
        bytes memory workflow = abi.encode(_execution);

        newWorkflow.workflow = workflow;
        newWorkflow.count = _count;
    }

    function executeFromDEP(
        address vault7579,
        uint256 workflowId
    )
        external
        returns (bytes[] memory returnData)
    {
        EntryPointStorage storage eps = _getLocalStorage();
        if(eps.dep != msg.sender) {
            revert DEP_Unauthorized();
        }

        WorkflowScenario storage currentWorkflow = eps.workflows[workflowId];

        if(currentWorkflow.count == 0) {
            revert CounterLimitReached();
        }
        currentWorkflow.count--;

        (Execution[] memory executions) = abi.decode(currentWorkflow.workflow, (Execution[]));

        if(executions.length > 1) {
            return IERC7579Account(vault7579).executeFromExecutor(
                ExecLib.encodeSimpleBatch(), ExecLib.encodeBatch(executions)
            );
        } else {
            return IERC7579Account(vault7579).executeFromExecutor(
                ExecLib.encodeSimpleSingle(), ExecLib.encodeSingle(executions[0].target, executions[0].value, executions[0].callData)
            );
        }
    }

    function dittoEntryPoint() external view returns(address depAddress) {
        depAddress = _getLocalStorage().dep;
    }

    function getWorkflow(uint256 workflowId) external view returns(WorkflowScenario memory wf) {
        wf = _getLocalStorage().workflows[workflowId];
    }

    function getNextWorkflowId() external view returns(uint256 lastId) {
        lastId = _getLocalStorage().workflowIds;
    }

    function onInstall(bytes calldata data) external payable override { }

    function onUninstall(bytes calldata data) external payable override { }

    function isModuleType(uint256 moduleTypeId) external pure returns (bool) {
        return moduleTypeId == 2;
    }

    function isInitialized(address smartAccount) external pure returns (bool) {
        return false;
    }
}
