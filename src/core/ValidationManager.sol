// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IValidator, IModule, IExecutor, IHook, IPolicy, ISigner, IFallback} from "../interfaces/IERC7579Modules.sol";
import {IERC7579Account} from "../interfaces/IERC7579Account.sol";
import {PackedUserOperation} from "../interfaces/PackedUserOperation.sol";
import {SelectorManager} from "./SelectorManager.sol";
import {HookManager} from "./HookManager.sol";
import {ExecutorManager} from "./ExecutorManager.sol";
import {ValidationData, ValidAfter, ValidUntil, parseValidationData} from "../interfaces/IAccount.sol";
import {IAccountExecute} from "../interfaces/IAccountExecute.sol";
import {EIP712} from "solady/utils/EIP712.sol";
import {ModuleLib} from "../utils/ModuleLib.sol";
import {
    ValidationId,
    PolicyData,
    ValidationMode,
    ValidationType,
    ValidatorLib,
    PassFlag
} from "../utils/ValidationTypeLib.sol";

import {CALLTYPE_SINGLE, MODULE_TYPE_POLICY, MODULE_TYPE_SIGNER, MODULE_TYPE_VALIDATOR} from "../types/Constants.sol";

import {PermissionId, getValidationResult, CallType} from "../types/Types.sol";
import {_intersectValidationData} from "../utils/KernelValidationResult.sol";
import {
    PermissionSigMemory,
    PermissionDisableDataFormat,
    PermissionEnableDataFormat,
    UserOpSigEnableDataFormat,
    SelectorDataFormat,
    SelectorDataFormatWithExecutorData
} from "../types/Structs.sol";

import {
    VALIDATION_MODE_DEFAULT,
    VALIDATION_MODE_ENABLE,
    VALIDATION_TYPE_ROOT,
    VALIDATION_TYPE_VALIDATOR,
    VALIDATION_TYPE_PERMISSION,
    SKIP_USEROP,
    SKIP_SIGNATURE,
    VALIDATION_MANAGER_STORAGE_SLOT,
    MAX_NONCE_INCREMENT_SIZE,
    ENABLE_TYPE_HASH,
    KERNEL_WRAPPER_TYPE_HASH,
    MAGIC_VALUE_SIG_REPLAYABLE
} from "../types/Constants.sol";

abstract contract ValidationManager is EIP712, SelectorManager, HookManager, ExecutorManager {
    event RootValidatorUpdated(ValidationId rootValidator);
    event ValidatorInstalled(IValidator validator, uint32 nonce);
    event PermissionInstalled(PermissionId permission, uint32 nonce);
    event NonceInvalidated(uint32 nonce);
    event ValidatorUninstalled(IValidator validator);
    event PermissionUninstalled(PermissionId permission);
    event SelectorSet(bytes4 selector, ValidationId vId, bool allowed);

    error InvalidMode();
    error InvalidValidator();
    error InvalidSignature();
    error EnableNotApproved();
    error PolicySignatureOrderError();
    error SignerPrefixNotPresent();
    error PolicyDataTooLarge();
    error InvalidValidationType();
    error InvalidNonce();
    error PolicyFailed(uint256 i);
    error PermissionNotAlllowedForUserOp();
    error PermissionNotAlllowedForSignature();
    error PermissionDataLengthMismatch();
    error NonceInvalidationError();
    error RootValidatorCannotBeRemoved();

    // erc7579 plugins
    struct ValidationConfig {
        uint32 nonce; // 4 bytes
        IHook hook; // 20 bytes address(1) : hook not required, address(0) : validator not installed
    }

    struct PermissionConfig {
        PassFlag permissionFlag;
        ISigner signer;
        PolicyData[] policyData;
    }

    struct ValidationStorage {
        ValidationId rootValidator;
        uint32 currentNonce;
        uint32 validNonceFrom;
        mapping(ValidationId => ValidationConfig) validationConfig;
        mapping(ValidationId => mapping(bytes4 => bool)) allowedSelectors;
        // validation = validator | permission
        // validator == 1 validator
        // permission == 1 signer + N policies
        mapping(PermissionId => PermissionConfig) permissionConfig;
    }

    function rootValidator() external view returns (ValidationId) {
        return _validationStorage().rootValidator;
    }

    function currentNonce() external view returns (uint32) {
        return _validationStorage().currentNonce;
    }

    function validNonceFrom() external view returns (uint32) {
        return _validationStorage().validNonceFrom;
    }

    function isAllowedSelector(ValidationId vId, bytes4 selector) external view returns (bool) {
        return _validationStorage().allowedSelectors[vId][selector];
    }

    function validationConfig(ValidationId vId) external view returns (ValidationConfig memory) {
        return _validationStorage().validationConfig[vId];
    }

    function permissionConfig(PermissionId pId) external view returns (PermissionConfig memory) {
        return (_validationStorage().permissionConfig[pId]);
    }

    function _validationStorage() internal pure returns (ValidationStorage storage state) {
        assembly {
            state.slot := VALIDATION_MANAGER_STORAGE_SLOT
        }
    }

    function _setRootValidator(ValidationId _rootValidator) internal {
        ValidationStorage storage vs = _validationStorage();
        vs.rootValidator = _rootValidator;
        emit RootValidatorUpdated(_rootValidator);
    }

    function _invalidateNonce(uint32 nonce) internal {
        ValidationStorage storage state = _validationStorage();
        if (state.currentNonce + MAX_NONCE_INCREMENT_SIZE < nonce) {
            revert NonceInvalidationError();
        }
        if (nonce <= state.validNonceFrom) {
            revert InvalidNonce();
        }
        state.validNonceFrom = nonce;
        if (state.currentNonce < state.validNonceFrom) {
            state.currentNonce = state.validNonceFrom;
        }
    }

    // allow installing multiple validators with same nonce
    function _installValidations(
        ValidationId[] calldata validators,
        ValidationConfig[] memory configs,
        bytes[] calldata validatorData,
        bytes[] calldata hookData
    ) internal {
        unchecked {
            for (uint256 i = 0; i < validators.length; i++) {
                _installValidation(validators[i], configs[i], validatorData[i], hookData[i]);
            }
        }
    }

    function _setSelector(ValidationId vId, bytes4 selector, bool allowed) internal {
        ValidationStorage storage state = _validationStorage();
        state.allowedSelectors[vId][selector] = allowed;
        emit SelectorSet(selector, vId, allowed);
    }

    // for uninstall, we support uninstall for validator mode by calling onUninstall
    // but for permission mode, we do it naively by setting hook to address(0).
    // it is more recommended to use a nonce revoke to make sure the validator has been revoked
    // also, we are not calling hook.onInstall here
    function _uninstallValidation(ValidationId vId, bytes calldata validatorData) internal returns (IHook hook) {
        ValidationStorage storage state = _validationStorage();
        if (vId == state.rootValidator) {
            revert RootValidatorCannotBeRemoved();
        }
        hook = state.validationConfig[vId].hook;
        state.validationConfig[vId].hook = IHook(address(0));
        ValidationType vType = ValidatorLib.getType(vId);
        if (vType == VALIDATION_TYPE_VALIDATOR) {
            IValidator validator = ValidatorLib.getValidator(vId);
            ModuleLib.uninstallModule(address(validator), validatorData);
            emit IERC7579Account.ModuleUninstalled(MODULE_TYPE_VALIDATOR, address(validator));
        } else if (vType == VALIDATION_TYPE_PERMISSION) {
            PermissionId permission = ValidatorLib.getPermissionId(vId);
            _uninstallPermission(permission, validatorData);
        } else {
            revert InvalidValidationType();
        }
    }

    function _uninstallPermission(PermissionId pId, bytes calldata data) internal {
        PermissionDisableDataFormat calldata permissionDisableData;
        assembly {
            permissionDisableData := data.offset
        }
        PermissionConfig storage config = _validationStorage().permissionConfig[pId];
        unchecked {
            if (permissionDisableData.data.length != config.policyData.length + 1) {
                revert PermissionDataLengthMismatch();
            }
            PolicyData[] storage policyData = config.policyData;
            for (uint256 i = 0; i < policyData.length; i++) {
                (, IPolicy policy) = ValidatorLib.decodePolicyData(policyData[i]);
                ModuleLib.uninstallModule(
                    address(policy), abi.encodePacked(bytes32(PermissionId.unwrap(pId)), permissionDisableData.data[i])
                );
                emit IERC7579Account.ModuleUninstalled(MODULE_TYPE_POLICY, address(policy));
            }
            delete _validationStorage().permissionConfig[pId].policyData;
            ModuleLib.uninstallModule(
                address(config.signer),
                abi.encodePacked(
                    bytes32(PermissionId.unwrap(pId)), permissionDisableData.data[permissionDisableData.data.length - 1]
                )
            );
            emit IERC7579Account.ModuleUninstalled(MODULE_TYPE_SIGNER, address(config.signer));
        }
        config.signer = ISigner(address(0));
        config.permissionFlag = PassFlag.wrap(bytes2(0));
    }

    function _installValidation(
        ValidationId vId,
        ValidationConfig memory config,
        bytes calldata validatorData,
        bytes calldata hookData
    ) internal {
        ValidationStorage storage state = _validationStorage();
        if (state.validationConfig[vId].nonce == state.currentNonce) {
            // only increase currentNonce when vId's currentNonce is same
            unchecked {
                state.currentNonce++;
            }
        }
        if (config.hook == IHook(address(0))) {
            config.hook = IHook(address(1));
        }
        if (state.currentNonce != config.nonce || state.validationConfig[vId].nonce >= config.nonce) {
            revert InvalidNonce();
        }
        state.validationConfig[vId] = config;
        if (config.hook != IHook(address(1))) {
            _installHook(config.hook, hookData);
        }
        ValidationType vType = ValidatorLib.getType(vId);
        if (vType == VALIDATION_TYPE_VALIDATOR) {
            IValidator validator = ValidatorLib.getValidator(vId);
            validator.onInstall(validatorData);
            emit IERC7579Account.ModuleInstalled(MODULE_TYPE_VALIDATOR, address(validator));
        } else if (vType == VALIDATION_TYPE_PERMISSION) {
            PermissionId permission = ValidatorLib.getPermissionId(vId);
            _installPermission(permission, validatorData);
        } else {
            revert InvalidValidationType();
        }
    }

    function _installPermission(PermissionId permission, bytes calldata permissionData) internal {
        ValidationStorage storage state = _validationStorage();
        PermissionEnableDataFormat calldata permissionEnableData;
        assembly {
            permissionEnableData := permissionData.offset
        }
        bytes[] calldata data = permissionEnableData.data;
        // allow up to 0xfe, 0xff is dedicated for signer
        if (data.length > 254 || data.length == 0) {
            revert PolicyDataTooLarge();
        }

        // clean up the policyData
        if (state.permissionConfig[permission].policyData.length > 0) {
            delete state.permissionConfig[permission].policyData;
        }
        unchecked {
            for (uint256 i = 0; i < data.length - 1; i++) {
                state.permissionConfig[permission].policyData.push(PolicyData.wrap(bytes22(data[i][0:22])));
                IPolicy(address(bytes20(data[i][2:22]))).onInstall(
                    abi.encodePacked(bytes32(PermissionId.unwrap(permission)), data[i][22:])
                );
                emit IERC7579Account.ModuleInstalled(MODULE_TYPE_POLICY, address(bytes20(data[i][2:22])));
            }
            // last permission data will be signer
            ISigner signer = ISigner(address(bytes20(data[data.length - 1][2:22])));
            state.permissionConfig[permission].signer = signer;
            state.permissionConfig[permission].permissionFlag = PassFlag.wrap(bytes2(data[data.length - 1][0:2]));
            signer.onInstall(abi.encodePacked(bytes32(PermissionId.unwrap(permission)), data[data.length - 1][22:]));
            emit IERC7579Account.ModuleInstalled(MODULE_TYPE_SIGNER, address(signer));
        }
    }

    function _doValidation(ValidationMode vMode, ValidationId vId, PackedUserOperation calldata op, bytes32 userOpHash)
        internal
        returns (ValidationData validationData)
    {
        ValidationStorage storage state = _validationStorage();
        PackedUserOperation memory userOp = op;
        bytes calldata userOpSig = op.signature;
        unchecked {
            {
                bool isReplayable;
                if (userOpSig.length >= 32 && bytes32(userOpSig[0:32]) == MAGIC_VALUE_SIG_REPLAYABLE) {
                    // when replayable
                    userOpSig = userOpSig[32:];
                    userOp.signature = userOpSig;
                    isReplayable = true;
                    userOpHash = replayableUserOpHash(op, msg.sender); // NOTE : msg.sender will be entrypoint
                }

                if (vMode == VALIDATION_MODE_ENABLE) {
                    (validationData, userOpSig) = _enableMode(vId, userOpSig, isReplayable);
                    userOp.signature = userOpSig;
                }
            }

            ValidationType vType = ValidatorLib.getType(vId);
            if (vType == VALIDATION_TYPE_VALIDATOR) {
                validationData = _intersectValidationData(
                    validationData,
                    ValidationData.wrap(ValidatorLib.getValidator(vId).validateUserOp(userOp, userOpHash))
                );
            } else {
                PermissionId pId = ValidatorLib.getPermissionId(vId);
                if (PassFlag.unwrap(state.permissionConfig[pId].permissionFlag) & PassFlag.unwrap(SKIP_USEROP) != 0) {
                    revert PermissionNotAlllowedForUserOp();
                }
                (ValidationData policyCheck, ISigner signer) = _checkUserOpPolicy(pId, userOp, userOpSig);
                validationData = _intersectValidationData(validationData, policyCheck);
                validationData = _intersectValidationData(
                    validationData,
                    ValidationData.wrap(
                        signer.checkUserOpSignature(bytes32(PermissionId.unwrap(pId)), userOp, userOpHash)
                    )
                );
            }
        }
    }

    function replayableUserOpHash(PackedUserOperation calldata userOp, address entryPoint)
        public
        pure
        returns (bytes32)
    {
        address sender = getSender(userOp);
        uint256 nonce = userOp.nonce;
        bytes32 hashInitCode = calldataKeccak(userOp.initCode);
        bytes32 hashCallData = calldataKeccak(userOp.callData);
        bytes32 accountGasLimits = userOp.accountGasLimits;
        uint256 preVerificationGas = userOp.preVerificationGas;
        bytes32 gasFees = userOp.gasFees;
        bytes32 hashPaymasterAndData = calldataKeccak(userOp.paymasterAndData);

        return keccak256(
            abi.encode(
                keccak256(
                    abi.encode(
                        sender,
                        nonce,
                        hashInitCode,
                        hashCallData,
                        accountGasLimits,
                        preVerificationGas,
                        gasFees,
                        hashPaymasterAndData
                    )
                ),
                entryPoint,
                uint256(0)
            )
        );
    }

    function _enableMode(ValidationId vId, bytes calldata packedData, bool isReplayable)
        internal
        returns (ValidationData validationData, bytes calldata userOpSig)
    {
        UserOpSigEnableDataFormat calldata enableData;
        assembly {
            enableData := add(packedData.offset, 20)
        }
        address hook = address(bytes20(packedData[0:20]));
        validationData = _enableValidationWithSig(vId, hook, enableData, isReplayable);

        return (validationData, enableData.userOpSig);
    }

    function _enableValidationWithSig(
        ValidationId vId,
        address hook,
        UserOpSigEnableDataFormat calldata enableData,
        bool isReplayable
    ) internal returns (ValidationData validationData) {
        (ValidationConfig memory config, bytes32 digest) = _enableDigest(vId, hook, enableData, isReplayable);
        validationData = _checkEnableSig(digest, enableData.enableSig);
        _installValidation(vId, config, enableData.validatorData, enableData.hookData);
        _configureSelector(enableData.selectorData);
        _setSelector(vId, bytes4(enableData.selectorData[0:4]), true);
    }

    function _checkEnableSig(bytes32 digest, bytes calldata enableSig)
        internal
        view
        returns (ValidationData validationData)
    {
        ValidationStorage storage state = _validationStorage();
        ValidationType vType = ValidatorLib.getType(state.rootValidator);
        bytes4 result;
        if (vType == VALIDATION_TYPE_VALIDATOR) {
            IValidator validator = ValidatorLib.getValidator(state.rootValidator);
            result = validator.isValidSignatureWithSender(address(this), digest, enableSig);
        } else if (vType == VALIDATION_TYPE_PERMISSION) {
            PermissionId pId = ValidatorLib.getPermissionId(state.rootValidator);
            ISigner signer;
            (signer, validationData, enableSig) = _checkSignaturePolicy(pId, address(this), digest, enableSig);
            result = signer.checkSignature(bytes32(PermissionId.unwrap(pId)), address(this), digest, enableSig);
        } else {
            revert InvalidValidationType();
        }
        if (result != 0x1626ba7e) {
            revert EnableNotApproved();
        }
    }

    function _configureSelector(bytes calldata selectorData) internal {
        bytes4 selector = bytes4(selectorData[0:4]);

        if (selectorData.length >= 4) {
            if (selectorData.length >= 44) {
                SelectorDataFormat calldata data;
                assembly {
                    data := add(selectorData.offset, 44)
                }
                // install selector with hook and target contract
                IModule selectorModule = IModule(address(bytes20(selectorData[4:24])));
                if (
                    CallType.wrap(bytes1(data.selectorInitData[0])) == CALLTYPE_SINGLE && selectorModule.isModuleType(2)
                ) {
                    // also adds as executor when fallback module is also a executor
                    SelectorDataFormatWithExecutorData calldata dataWithExecutor;
                    assembly {
                        dataWithExecutor := data
                    }
                    IHook executorHook = IHook(address(bytes20(dataWithExecutor.executorHookData[0:20])));
                    // if module is also executor, install as executor
                    _installExecutorWithoutInit(IExecutor(address(selectorModule)), executorHook);
                    _installHook(executorHook, dataWithExecutor.executorHookData[20:]);
                }
                _installSelector(
                    selector,
                    address(selectorModule),
                    IHook(address(bytes20(selectorData[24:44]))),
                    data.selectorInitData
                );
                _installHook(IHook(address(bytes20(selectorData[24:44]))), data.hookInitData);
            } else {
                // set without install
                require(selectorData.length == 4, "Invalid selectorData");
            }
        }
    }

    function _enableDigest(
        ValidationId vId,
        address hook,
        UserOpSigEnableDataFormat calldata enableData,
        bool isReplayable
    ) internal view returns (ValidationConfig memory config, bytes32 digest) {
        ValidationStorage storage state = _validationStorage();
        config.hook = IHook(hook);
        config.nonce = state.currentNonce;

        bytes32 structHash = keccak256(
            abi.encode(
                ENABLE_TYPE_HASH,
                ValidationId.unwrap(vId),
                config.nonce,
                config.hook,
                calldataKeccak(enableData.validatorData),
                calldataKeccak(enableData.hookData),
                calldataKeccak(enableData.selectorData)
            )
        );

        digest = isReplayable ? _chainAgnosticHashTypedData(structHash) : _hashTypedData(structHash);
    }

    function _checkUserOpPolicy(PermissionId pId, PackedUserOperation memory userOp, bytes calldata userOpSig)
        internal
        returns (ValidationData validationData, ISigner signer)
    {
        ValidationStorage storage state = _validationStorage();
        PolicyData[] storage policyData = state.permissionConfig[pId].policyData;
        unchecked {
            for (uint256 i = 0; i < policyData.length; i++) {
                (PassFlag flag, IPolicy policy) = ValidatorLib.decodePolicyData(policyData[i]);
                uint8 idx = uint8(bytes1(userOpSig[0]));
                if (idx == i) {
                    // we are using uint64 length
                    uint256 length = uint64(bytes8(userOpSig[1:9]));
                    userOp.signature = userOpSig[9:9 + length];
                    userOpSig = userOpSig[9 + length:];
                } else if (idx < i) {
                    // signature is not in order
                    revert PolicySignatureOrderError();
                } else {
                    userOp.signature = "";
                }
                if (PassFlag.unwrap(flag) & PassFlag.unwrap(SKIP_USEROP) == 0) {
                    ValidationData vd =
                        ValidationData.wrap(policy.checkUserOpPolicy(bytes32(PermissionId.unwrap(pId)), userOp));
                    address result = getValidationResult(vd);
                    if (result != address(0)) {
                        revert PolicyFailed(i);
                    }
                    validationData = _intersectValidationData(validationData, vd);
                }
            }
            if (uint8(bytes1(userOpSig[0])) != 255) {
                revert SignerPrefixNotPresent();
            }
            userOp.signature = userOpSig[1:];
            return (validationData, state.permissionConfig[pId].signer);
        }
    }

    function _checkSignaturePolicy(PermissionId pId, address caller, bytes32 digest, bytes calldata sig)
        internal
        view
        returns (ISigner, ValidationData, bytes calldata)
    {
        ValidationStorage storage state = _validationStorage();
        PermissionSigMemory memory mSig;
        mSig.permission = pId;
        mSig.caller = caller;
        mSig.digest = digest;
        _checkPermissionPolicy(mSig, state, sig);
        if (uint8(bytes1(sig[0])) != 255) {
            revert SignerPrefixNotPresent();
        }
        sig = sig[1:];
        return (state.permissionConfig[mSig.permission].signer, mSig.validationData, sig);
    }

    function _checkPermissionPolicy(
        PermissionSigMemory memory mSig,
        ValidationStorage storage state,
        bytes calldata sig
    ) internal view {
        PolicyData[] storage policyData = state.permissionConfig[mSig.permission].policyData;
        unchecked {
            for (uint256 i = 0; i < policyData.length; i++) {
                (mSig.flag, mSig.policy) = ValidatorLib.decodePolicyData(policyData[i]);
                mSig.idx = uint8(bytes1(sig[0]));
                if (mSig.idx == i) {
                    // we are using uint64 length
                    mSig.length = uint64(bytes8(sig[1:9]));
                    mSig.permSig = sig[9:9 + mSig.length];
                    sig = sig[9 + mSig.length:];
                } else if (mSig.idx < i) {
                    // signature is not in order
                    revert PolicySignatureOrderError();
                } else {
                    mSig.permSig = sig[0:0];
                }

                if (PassFlag.unwrap(mSig.flag) & PassFlag.unwrap(SKIP_SIGNATURE) == 0) {
                    ValidationData vd = ValidationData.wrap(
                        mSig.policy.checkSignaturePolicy(
                            bytes32(PermissionId.unwrap(mSig.permission)), mSig.caller, mSig.digest, mSig.permSig
                        )
                    );
                    address result = getValidationResult(vd);
                    if (result != address(0)) {
                        revert PolicyFailed(i);
                    }

                    mSig.validationData = _intersectValidationData(mSig.validationData, vd);
                }
            }
        }
    }

    function _checkPermissionSignature(
        PermissionId pId,
        address caller,
        bytes32 hash,
        bytes calldata sig,
        bool isReplayable
    ) internal view returns (bytes4) {
        (ISigner signer, ValidationData valdiationData, bytes calldata validatorSig) =
            _checkSignaturePolicy(pId, caller, hash, sig);
        (ValidAfter validAfter, ValidUntil validUntil,) = parseValidationData(ValidationData.unwrap(valdiationData));
        if (block.timestamp < ValidAfter.unwrap(validAfter) || block.timestamp > ValidUntil.unwrap(validUntil)) {
            return 0xffffffff;
        }
        return signer.checkSignature(
            bytes32(PermissionId.unwrap(pId)), caller, _toWrappedHash(hash, isReplayable), validatorSig
        );
    }

    function _toWrappedHash(bytes32 hash, bool isReplayable) internal view returns (bytes32) {
        bytes32 structHash = keccak256(abi.encode(KERNEL_WRAPPER_TYPE_HASH, hash));
        return isReplayable ? _chainAgnosticHashTypedData(structHash) : _hashTypedData(structHash);
    }

    function calldataKeccak(bytes calldata data) internal pure returns (bytes32 ret) {
        assembly ("memory-safe") {
            let mem := mload(0x40)
            let len := data.length
            calldatacopy(mem, data.offset, len)
            ret := keccak256(mem, len)
        }
    }

    function getSender(PackedUserOperation calldata userOp) internal pure returns (address) {
        address data;
        //read sender from userOp, which is first userOp member (saves 800 gas...)
        assembly {
            data := calldataload(userOp)
        }
        return address(uint160(data));
    }

    /// @dev Returns the EIP-712 domain separator.
    function _buildChainAgnosticDomainSeparator() private view returns (bytes32 separator) {
        // We will use `separator` to store the name hash to save a bit of gas.
        bytes32 versionHash;
        (string memory name, string memory version) = _domainNameAndVersion();
        separator = keccak256(bytes(name));
        versionHash = keccak256(bytes(version));
        /// @solidity memory-safe-assembly
        assembly {
            let m := mload(0x40) // Load the free memory pointer.
            mstore(m, _DOMAIN_TYPEHASH)
            mstore(add(m, 0x20), separator) // Name hash.
            mstore(add(m, 0x40), versionHash)
            mstore(add(m, 0x60), 0x00) //  NOTE : user chainId == 0 as eip 7702 did
            mstore(add(m, 0x80), address())
            separator := keccak256(m, 0xa0)
        }
    }

    function _chainAgnosticHashTypedData(bytes32 structHash) internal view virtual returns (bytes32 digest) {
        // we don't do cache stuff here
        digest = _buildChainAgnosticDomainSeparator();
        /// @solidity memory-safe-assembly
        assembly {
            // Compute the digest.
            mstore(0x00, 0x1901000000000000) // Store "\x19\x01".
            mstore(0x1a, digest) // Store the domain separator.
            mstore(0x3a, structHash) // Store the struct hash.
            digest := keccak256(0x18, 0x42)
            // Restore the part of the free memory slot that was overwritten.
            mstore(0x3a, 0)
        }
    }
}
