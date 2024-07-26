// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { IModule } from "./IERC7579Modules.sol";
import { Execution } from "../types/Structs.sol";

interface IDittoAdapter is IModule {

    error CounterLimitReached();
    error DEP_Unauthorized();

    struct WorkflowScenario {
        bytes workflow;
        uint256 count;
    }

    struct EntryPointStorage {
        mapping(uint256 => WorkflowScenario) workflows;
        uint256 workflowIds;
        address dep;
    }

    function addWorkflow(Execution[] memory _execution, uint256 _count) external;

    function executeFromDEP(address vault7579, uint256 workflowId) external returns (bytes[] memory returnData);

    function init() external; 

    function getWorkflow(uint256 workflowId) external view returns(WorkflowScenario memory wf);

    function getNextWorkflowId() external view returns(uint256 lastId);

    function dittoEntryPoint() external view returns(address depAddress);
}
