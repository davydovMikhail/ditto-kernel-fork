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

contract MockCallee {
    uint256 public value;

    event MockEvent(address indexed caller, address indexed here);

    function setValue(uint256 _value) public {
        value = _value;
    }

    function emitEvent(bool shouldFail) public {
        if (shouldFail) {
            revert("Hello");
        }
        emit MockEvent(msg.sender, address(this));
    }
}

contract dep is Test {
    uint256 polygonFork;

    address stakerOwner;
    Kernel kernel;
    KernelFactory factory;
    FactoryStaker staker;
    IEntryPoint entrypoint;
    ValidationId rootValidation;
    bytes[] initConfig;
    DittoAdapter adapterModule;
    DittoEntryPoint dittoEntryPoint;

    struct RootValidationConfig {
        IHook hook;
        bytes validatorData;
        bytes hookData;
    }

    RootValidationConfig rootValidationConfig;
    MockValidator mockValidator;
    MockCallee callee;
    MockFallback mockFallback;

    MockTarget targetCounter;

    address dittoOperator;

    IValidator enabledValidator;
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

    function needEnable(ValidationType vType) internal view returns (bool) {
        if (vType == VALIDATION_TYPE_VALIDATOR) {
            if (
                address(kernel.validationConfig(ValidatorLib.validatorToIdentifier(enabledValidator)).hook)
                    == address(0)
            ) {
                return true;
            }
            return false;
        } else if (vType == VALIDATION_TYPE_PERMISSION) {
            return address(kernel.validationConfig(ValidatorLib.permissionToIdentifier(enabledPermission)).hook)
                == address(0);
        } else if (vType == VALIDATION_TYPE_ROOT) {
            return false;
        } else {
            revert("Invalid validation type");
        }
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
                bytes20(address(enabledValidator)),
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

    function getEnableDigest(ValidationType vType, bool overrideValidation, bytes memory selectorData)
        internal
        view
        returns (bytes32)
    {
        uint32 nonce = kernel.currentNonce();
        if (overrideValidation) {
            nonce = nonce + 1;
        }
        ValidationId vId;
        IHook hook;
        bytes memory validatorData;
        bytes memory hookData;
        if (vType == VALIDATION_TYPE_VALIDATOR) {
            vId = ValidatorLib.validatorToIdentifier(enabledValidator);
            hook = validationConfig.hook;
            validatorData = validationConfig.validatorData;
            hookData = validationConfig.hookData;
        } else if (vType == VALIDATION_TYPE_PERMISSION) {
            vId = ValidatorLib.permissionToIdentifier(enabledPermission);
            hook = permissionConfig.hook;
            validatorData = encodePermissionsEnableData();
            hookData = permissionConfig.hookData;
        } else {
            revert("Invalid validation type");
        }

        bytes32 hash = keccak256(
            abi.encode(
                keccak256(
                    "Enable(bytes21 validationId,uint32 nonce,address hook,bytes validatorData,bytes hookData,bytes selectorData)"
                ),
                ValidationId.unwrap(vId),
                uint256(nonce),
                hook,
                keccak256(validatorData),
                keccak256(abi.encodePacked(hex"ff", hookData)),
                keccak256(selectorData)
            )
        );

        bytes32 digest =
            keccak256(abi.encodePacked("\x19\x01", _buildDomainSeparator("Kernel", "0.3.1", address(kernel)), hash));

        return digest;
    }

    function encodeSelectorData(bool isFallback, bool isExecutor) internal view returns (bytes memory) {
        if (isFallback && isExecutor) {
            return abi.encodePacked(
                MockFallback.setData.selector,
                address(mockFallback),
                address(1),
                abi.encode(abi.encodePacked(hex"00", "MockFallbackInit"), hex"", abi.encodePacked(address(0))) // TODO add executor hook test
            );
        } else if (isFallback) {
            return abi.encodePacked(
                MockFallback.setData.selector,
                address(mockFallback),
                address(1),
                abi.encode(abi.encodePacked(hex"00", "MockFallbackInit"), hex"")
            );
        } else if (!isFallback && !isExecutor) {
            return abi.encodePacked(Kernel.execute.selector);
        } else {
            revert("Invalid selector data");
        }
    }

    function getValidationId(ValidationType vType) internal view returns (ValidationId) {
        if (vType == VALIDATION_TYPE_VALIDATOR) {
            return ValidatorLib.validatorToIdentifier(enabledValidator);
        } else if (vType == VALIDATION_TYPE_PERMISSION) {
            return ValidatorLib.permissionToIdentifier(enabledPermission);
        } else {
            revert("Invalid validation type");
        }
    }

    function getEnableSignature(
        ValidationType vType,
        bytes32 digest,
        bytes memory selectorData,
        PackedUserOperation memory op,
        bool successEnable,
        bool successUserOp
    ) internal returns (bytes memory) {
        bytes memory enableSig = _rootSignDigest(digest, successEnable);
        bytes memory userOpSig = _signUserOp(vType, op, successUserOp);
        IHook hook;
        bytes memory validatorData;
        bytes memory hookData;
        if (vType == VALIDATION_TYPE_VALIDATOR) {
            hook = validationConfig.hook;
            validatorData = validationConfig.validatorData;
            hookData = validationConfig.hookData;
        } else if (vType == VALIDATION_TYPE_PERMISSION) {
            hook = permissionConfig.hook;
            validatorData = encodePermissionsEnableData();
            hookData = permissionConfig.hookData;
        } else {
            revert("Invalid validation type");
        }
        return encodeEnableSignature(
            hook, validatorData, abi.encodePacked(hex"ff", hookData), selectorData, enableSig, userOpSig
        );
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
        bool enable = needEnable(vType);
        op = PackedUserOperation({
            sender: address(kernel),
            nonce: encodeNonce(vType, enable),
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
        if (enable) {
            bytes memory selectorData = encodeSelectorData(isFallback, isExecutor);
            bytes32 digest = getEnableDigest(vType, false, selectorData);
            op.signature = getEnableSignature(vType, digest, selectorData, op, successEnable, successUserOp);
        } else {
            op.signature = _signUserOp(vType, op, successUserOp);
        }
    }

    function setUp() public {
        polygonFork = vm.createSelectFork("polygon");

        address entrypointAddress = 0x0000000071727De22E5E9d8BAf0edAc6f37da032;
        address factoryAddress = 0xaac5D4240AF87249B3f71BC8E4A2cae074A3E419;

        enabledPermission = PermissionId.wrap(bytes4(0xdeadbeef));
        entrypoint = IEntryPoint(entrypointAddress);
        factory = KernelFactory(factoryAddress);
        mockFallback = new MockFallback();

        _setRootValidationConfig();
        _setEnableValidatorConfig();
        _setEnablePermissionConfig();
        
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

    function encodeEnableSignature(
        IHook hook,
        bytes memory validatorData,
        bytes memory hookData,
        bytes memory selectorData,
        bytes memory enableSig,
        bytes memory userOpSig
    ) internal pure returns (bytes memory) {
        return abi.encodePacked(
            abi.encodePacked(hook), abi.encode(validatorData, hookData, selectorData, enableSig, userOpSig)
        );
    }

    // things to override on test
    function _setRootValidationConfig() internal virtual {
        mockValidator = new MockValidator();
        rootValidation = ValidatorLib.validatorToIdentifier(mockValidator);
    }

    function _setEnableValidatorConfig() internal virtual {
        enabledValidator = new MockValidator();
    }

    function _setEnablePermissionConfig() internal virtual {
        IPolicy[] memory policies = new IPolicy[](2);
        MockPolicy mockPolicy = new MockPolicy();
        MockPolicy mockPolicy2 = new MockPolicy();
        policies[0] = mockPolicy;
        policies[1] = mockPolicy2;
        bytes[] memory policyData = new bytes[](2);
        policyData[0] = "policy1";
        policyData[1] = "policy2";
        MockSigner mockSigner = new MockSigner();

        permissionConfig.policies = policies;
        permissionConfig.signer = mockSigner;
        permissionConfig.policyData = policyData;
        permissionConfig.signerData = "signer";
    }

    function _rootSignDigest(bytes32 digest, bool success) internal virtual returns (bytes memory data) {
        if (success) {
            data = "enableSig";
            mockValidator.sudoSetValidSig(data);
        } else {
            data = "failEnableSig";
        }
    }

    function _signUserOp(ValidationType vType, PackedUserOperation memory op, bool success)
        internal
        virtual
        returns (bytes memory data)
    {
        if (vType == VALIDATION_TYPE_VALIDATOR) {
            return _validatorSignUserOp(op, success);
        } else if (vType == VALIDATION_TYPE_PERMISSION) {
            return _permissionSignUserOp(op, success);
        } else if (vType == VALIDATION_TYPE_ROOT) {
            return _rootSignUserOp(op, success);
        }
        revert("Invalid validation type");
    }

    function _rootSignUserOp(PackedUserOperation memory op, bool success) internal virtual returns (bytes memory) {
        mockValidator.sudoSetSuccess(success);
        return success ? abi.encodePacked("success") : abi.encodePacked("failure");
    }

    function _validatorSignUserOp(PackedUserOperation memory, bool success)
        internal
        virtual
        returns (bytes memory data)
    {
        MockValidator(address(enabledValidator)).sudoSetSuccess(success);
        if (success) {
            return "userOpSig";
        } else {
            return "failUserOpSig";
        }
    }

    function _validatorSignDigest(bytes32 digest, bool success) internal virtual returns (bytes memory data) {
        if (success) {
            data = "enableSig";
            MockValidator(address(enabledValidator)).sudoSetValidSig(data);
        } else {
            data = "failEnableSig";
        }
    }

    function _permissionSignUserOp(PackedUserOperation memory op, bool success)
        internal
        virtual
        returns (bytes memory data)
    {
        MockPolicy(address(permissionConfig.policies[0])).sudoSetValidSig(
            address(kernel), bytes32(PermissionId.unwrap(enabledPermission)), "policy1"
        );
        MockPolicy(address(permissionConfig.policies[1])).sudoSetValidSig(
            address(kernel), bytes32(PermissionId.unwrap(enabledPermission)), "policy2"
        );
        MockSigner(address(permissionConfig.signer)).sudoSetValidSig(
            address(kernel),
            bytes32(PermissionId.unwrap(enabledPermission)),
            success ? abi.encodePacked("userOpSig") : abi.encodePacked("NO")
        );
        bytes[] memory sigs = _getPolicyAndSignerSig(op, success);
        for (uint8 i = 0; i < sigs.length - 1; i++) {
            if (sigs[i].length > 0) {
                data = abi.encodePacked(data, bytes1(i), bytes8(uint64(sigs[i].length)), sigs[i]);
            }
        }
        data = abi.encodePacked(data, bytes1(0xff), sigs[sigs.length - 1]);
    }

    function _permissionSignDigest(bytes32 digest, bool success) internal virtual returns (bytes memory data) {
        MockPolicy(address(permissionConfig.policies[0])).sudoSetPass(
            address(kernel), bytes32(PermissionId.unwrap(enabledPermission)), true
        );
        MockPolicy(address(permissionConfig.policies[1])).sudoSetPass(
            address(kernel), bytes32(PermissionId.unwrap(enabledPermission)), true
        );
        MockSigner(address(permissionConfig.signer)).sudoSetPass(
            address(kernel), bytes32(PermissionId.unwrap(enabledPermission)), success
        );
        return "hello world";
    }

    function _getPolicyAndSignerSig(PackedUserOperation memory op, bool success)
        internal
        returns (bytes[] memory data)
    {
        data = new bytes[](3);
        data[0] = "policy1";
        data[1] = "policy2";
        data[2] = "userOpSig";
    }

    function _buildDomainSeparator(string memory name, string memory version, address verifyingContract)
        internal
        view
        returns (bytes32)
    {
        bytes32 hashedName = keccak256(bytes(name));
        bytes32 hashedVersion = keccak256(bytes(version));
        bytes32 typeHash =
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

        return keccak256(abi.encode(typeHash, hashedName, hashedVersion, block.chainid, address(verifyingContract)));
    }

    function encodeExecute(address _to, uint256 _amount, bytes memory _data) internal view returns (bytes memory) {
        return abi.encodeWithSelector(
            kernel.execute.selector, ExecLib.encodeSimpleSingle(), ExecLib.encodeSingle(_to, _amount, _data)
        );
    }

    function encodePermissionsEnableData() internal view returns (bytes memory) {
        bytes[] memory permissions = new bytes[](permissionConfig.policies.length + 1);
        for (uint256 i = 0; i < permissions.length - 1; i++) {
            permissions[i] = abi.encodePacked(
                PolicyData.unwrap(ValidatorLib.encodePolicyData(false, false, address(permissionConfig.policies[i]))),
                permissionConfig.policyData[i]
            );
        }
        permissions[permissions.length - 1] = abi.encodePacked(
            PolicyData.unwrap(ValidatorLib.encodePolicyData(false, false, address(permissionConfig.signer))),
            permissionConfig.signerData
        );
        return abi.encode(permissions);
    }

}
