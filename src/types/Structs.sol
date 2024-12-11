// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {ValidationData, PermissionId, PassFlag} from "./Types.sol";
import {IPolicy} from "../interfaces/IERC7579Modules.sol";

struct Execution {
    address target;
    uint256 value;
    bytes callData;
}

// === for internal usage ===
struct PermissionSigMemory {
    uint8 idx;
    uint256 length;
    ValidationData validationData;
    PermissionId permission;
    PassFlag flag;
    IPolicy policy;
    bytes permSig;
    address caller;
    bytes32 digest;
}

struct PermissionDisableDataFormat {
    bytes[] data;
}

struct PermissionEnableDataFormat {
    bytes[] data;
}

struct UserOpSigEnableDataFormat {
    bytes validatorData;
    bytes hookData;
    bytes selectorData;
    bytes enableSig;
    bytes userOpSig;
}

struct SelectorDataFormat {
    bytes selectorInitData;
    bytes hookInitData;
}

struct SelectorDataFormatWithExecutorData {
    bytes selectorInitData;
    bytes hookInitData;
    bytes executorHookData;
}

struct InstallValidatorDataFormat {
    bytes validatorData;
    bytes hookData;
    bytes selectorData;
}

struct InstallExecutorDataFormat {
    bytes executorData;
    bytes hookData;
}

struct InstallFallbackDataFormat {
    bytes selectorData;
    bytes hookData;
}
