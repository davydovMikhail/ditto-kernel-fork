// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "../src/Kernel.sol";
import "../src/factory/KernelFactory.sol";
import "../src/factory/FactoryStaker.sol";
import "forge-std/Test.sol";
import "../src/mock/MockValidator.sol";
import "../src/mock/MockPolicy.sol";
import "../src/mock/MockSigner.sol";
import "../src/mock/MockFallback.sol";
import "../src/core/ValidationManager.sol";
import "../src/sdk/TestBase/erc4337Util.sol";
import "../src/types/Types.sol";
import "../src/types/Structs.sol";
import "../src/ditto-adapter/DittoAdapter.sol";
import "../src/ditto-adapter/DittoEntryPoint.sol";
import "../src/mock/MockTarget.sol";
import "../src/validator/ECDSAValidator.sol";

contract dep is Test {
    uint256 polygonFork;

    address stakerOwner;
    Kernel kernel;
    KernelFactory factory;
    FactoryStaker staker;
    IEntryPoint entrypoint;
    ECDSAValidator realValidator;
    ValidationId rootValidation;
    bytes[] initConfig;
    DittoAdapter adapterModule;
    DittoEntryPoint dittoEntryPoint;

    address owner;
    uint256 ownerKey;

    struct RootValidationConfig {
        IHook hook;
        bytes validatorData;
        bytes hookData;
    }

    RootValidationConfig rootValidationConfig;
    MockFallback mockFallback;

    MockTarget targetCounter;

    address dittoOperator;

    EnableValidatorConfig validationConfig;

    struct EnableValidatorConfig {
        IHook hook;
        bytes hookData;
        bytes validatorData;
    }

    PermissionId enabledPermission;
    EnablePermissionConfig permissionConfig;

    struct EnablePermissionConfig {
        IHook hook;
        bytes hookData;
        IPolicy[] policies;
        bytes[] policyData;
        ISigner signer;
        bytes signerData;
    }

    function encodeNonce(ValidationType vType, bool enable) internal view returns (uint256 nonce) {
        uint192 nonceKey = 0;
        if (vType == VALIDATION_TYPE_ROOT) {
            nonceKey = 0;
        } else if (vType == VALIDATION_TYPE_VALIDATOR) {
            ValidationMode mode = VALIDATION_MODE_DEFAULT;
            if (enable) {
                mode = VALIDATION_MODE_ENABLE;
            }
            nonceKey = ValidatorLib.encodeAsNonceKey(
                ValidationMode.unwrap(mode),
                ValidationType.unwrap(vType),
                bytes20(address(realValidator)),
                0 // parallel key
            );
        } else if (vType == VALIDATION_TYPE_PERMISSION) {
            ValidationMode mode = VALIDATION_MODE_DEFAULT;
            if (enable) {
                mode = VALIDATION_MODE_ENABLE;
            }
            nonceKey = ValidatorLib.encodeAsNonceKey(
                ValidationMode.unwrap(VALIDATION_MODE_ENABLE),
                ValidationType.unwrap(vType),
                bytes20(PermissionId.unwrap(enabledPermission)), // permission id
                0
            );
        } else {
            revert("Invalid validation type");
        }
        return entrypoint.getNonce(address(kernel), nonceKey);
    }

    function _prepareUserOp(
        ValidationType vType,
        bool isFallback,
        bool isExecutor,
        bytes memory callData,
        bool successEnable,
        bool successUserOp
    ) internal returns (PackedUserOperation memory op) {
        if (isFallback && isExecutor) {
            mockFallback.setExecutorMode(true);
        }
        op = PackedUserOperation({
            sender: address(kernel),
            nonce: encodeNonce(vType, false),
            initCode: address(kernel).code.length == 0
                ? abi.encodePacked(
                    address(staker), abi.encodeWithSelector(staker.deployWithFactory.selector, factory, initData(), bytes32(0))
                )
                : abi.encodePacked(hex""),
            callData: callData,
            accountGasLimits: bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))), // TODO make this dynamic
            preVerificationGas: 1000000,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: hex"", // TODO have paymaster test cases
            signature: hex""
        });
        op.signature = _signUserOp(vType, op, successUserOp);
    }

    function setUp() public {
        polygonFork = vm.createSelectFork("polygon");

        address entrypointAddress = 0x0000000071727De22E5E9d8BAf0edAc6f37da032;
        address factoryAddress = 0xaac5D4240AF87249B3f71BC8E4A2cae074A3E419;
        address ECDSAValidatorAddress = 0x845ADb2C711129d4f3966735eD98a9F09fC4cE57;

        enabledPermission = PermissionId.wrap(bytes4(0xdeadbeef));
        entrypoint = IEntryPoint(entrypointAddress);
        factory = KernelFactory(factoryAddress);
        realValidator = ECDSAValidator(ECDSAValidatorAddress);
        
        mockFallback = new MockFallback();

        _setRootValidationConfig();

        kernel = Kernel(payable(factory.getAddress(initData(), bytes32(0))));
        stakerOwner = makeAddr("StakerOwner");
        staker = new FactoryStaker(stakerOwner);
        vm.startPrank(stakerOwner);
        staker.approveFactory(factory, true);
        vm.stopPrank();

        adapterModule = new DittoAdapter();
        dittoOperator = makeAddr("DITTO_OPERATOR");
        
        dittoEntryPoint = new DittoEntryPoint(address(adapterModule), dittoOperator);
        assertEq(adapterModule.dittoEntryPoint(), address(dittoEntryPoint));
        targetCounter = new MockTarget();
    }

    function test_deployAccountFactory() public {
        uint256 beforeCodeLength = address(kernel).code.length;
        assertEq(beforeCodeLength == 0, true);
        vm.deal(address(kernel), 20e18);
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = _prepareUserOp(VALIDATION_TYPE_ROOT, false, false, hex"", true, true);
        entrypoint.handleOps(ops, payable(address(0xdeadbeef)));
        uint256 afterCodeLength = address(kernel).code.length;
        assertEq(beforeCodeLength < afterCodeLength, true);
    }

    function test_installModuleDitto() public {
        test_deployAccountFactory();
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = _prepareUserOp(
            VALIDATION_TYPE_ROOT,
            false,
            false,
            abi.encodeWithSelector(
                kernel.installModule.selector,
                2,
                address(adapterModule),
                abi.encodePacked(
                    address(0),
                    abi.encode(abi.encodePacked("executorData"), abi.encodePacked(""))
                )
            ),
            true,
            true
        );
        entrypoint.handleOps(ops, payable(address(0xdeadbeef)));
        assertEq(kernel.isModuleInstalled(MODULE_TYPE_EXECUTOR, address(adapterModule), ""), true);
    }

    function test_addingSimpleWorkflow() public returns(uint256) {
        bytes memory incrementValueOnTarget = abi.encodeCall(MockTarget.incrementValue, ());
        uint256 count = 10;
        uint256 nextWorkflowId = adapterModule.getNextWorkflowId();
        Execution[] memory executions = new Execution[](1);
        executions[0] = Execution({ target: address(targetCounter), value: 0, callData: incrementValueOnTarget });
        adapterModule.addWorkflow(
            executions,
            count
        );
        uint256 nextPlusOneWorkflowId = adapterModule.getNextWorkflowId();
        IDittoAdapter.WorkflowScenario memory wf = adapterModule.getWorkflow(nextWorkflowId);
        assertEq(nextWorkflowId + 1, nextPlusOneWorkflowId);
        bytes memory encodedExecutions = abi.encode(executions);

        assertEq(wf.workflow, encodedExecutions);
        assertEq(wf.count, count);
        return nextWorkflowId;
    }

    function test_addingBatchWorkflow() public returns(uint256) {
        bytes memory incrementValueOnTarget = abi.encodeCall(MockTarget.incrementValue, ());
        bytes memory incrementValueTwiceOnTarget = abi.encodeCall(MockTarget.incrementValueTwice, ());
        uint256 count = 10;
        uint256 nextWorkflowId = adapterModule.getNextWorkflowId();
        Execution[] memory executions = new Execution[](2);
        executions[0] = Execution({ target: address(targetCounter), value: 0, callData: incrementValueOnTarget });
        executions[1] = Execution({ target: address(targetCounter), value: 0, callData: incrementValueTwiceOnTarget });
        adapterModule.addWorkflow(
            executions,
            count
        );
        uint256 nextPlusOneWorkflowId = adapterModule.getNextWorkflowId();
        IDittoAdapter.WorkflowScenario memory wf = adapterModule.getWorkflow(nextWorkflowId);
        assertEq(nextWorkflowId + 1, nextPlusOneWorkflowId);
        bytes memory encodedExecutions = abi.encode(executions);

        assertEq(wf.workflow, encodedExecutions);
        assertEq(wf.count, count);
        return nextWorkflowId;
    }

    function testFuzz_Registration(uint256 workflowId) public {
        vm.prank(dittoOperator);
        dittoEntryPoint.registerWorkflow(workflowId);
        assertEq(dittoEntryPoint.isRegistered(workflowId), true);
    }

    function test_runSimpleWorkflowFromDEP() public {
        uint256 valueBefore = targetCounter.getValue();
        test_installModuleDitto();
        uint256 workflowId = test_addingSimpleWorkflow();
        testFuzz_Registration(workflowId);
        dittoEntryPoint.runWorkflow(address(kernel), workflowId);
        assertEq(targetCounter.getValue(), valueBefore + 1);
        IDittoEntryPoint.Workflow[] memory slice = dittoEntryPoint.getWorkflowSlice(0, 1);
        assertEq(slice[0].vaultAddress, address(kernel));
        assertEq(slice[0].workflowId, workflowId);
    }

    function test_runBatchWorkflowFromDEP() public {
        uint256 valueBefore = targetCounter.getValue();
        test_installModuleDitto();
        uint256 workflowId = test_addingBatchWorkflow();
        testFuzz_Registration(workflowId);
        dittoEntryPoint.runWorkflow(address(kernel), workflowId);
        assertEq(targetCounter.getValue(), valueBefore + 3);
        IDittoEntryPoint.Workflow[] memory slice = dittoEntryPoint.getWorkflowSlice(0, 1);
        assertEq(slice[0].vaultAddress, address(kernel));
        assertEq(slice[0].workflowId, workflowId);
    }

    function initData() internal view returns (bytes memory) {
        return abi.encodeWithSelector(
            Kernel.initialize.selector,
            rootValidation,
            rootValidationConfig.hook,
            rootValidationConfig.validatorData,
            rootValidationConfig.hookData,
            initConfig
        );
    }

    function _rootSignUserOp(PackedUserOperation memory op, bool success)
        internal
        view
        returns (bytes memory)
    {
        bytes32 hash = entrypoint.getUserOpHash(op);
        return _rootSignDigest(hash, success);
    }

    function _rootSignDigest(bytes32 digest, bool success) internal view returns (bytes memory data) {
        unchecked {
            if (!success) {
                digest = bytes32(uint256(digest) - 1);
            }
        }
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, ECDSA.toEthSignedMessageHash(digest));
        bytes memory sig = abi.encodePacked(r, s, v);
        return sig;
    }

    function _setRootValidationConfig() internal {
        (owner, ownerKey) = makeAddrAndKey("OwnerAndSigner");
        
        rootValidation = ValidatorLib.validatorToIdentifier(realValidator);
        rootValidationConfig =
            RootValidationConfig({hook: IHook(address(0)), hookData: hex"", validatorData: abi.encodePacked(owner)});
    }

    function _signUserOp(ValidationType vType, PackedUserOperation memory op, bool success)
        internal
        virtual
        returns (bytes memory data)
    {
        if (vType == VALIDATION_TYPE_ROOT) {
            return _rootSignUserOp(op, success);
        }
        revert("Invalid validation type");
    }
}
