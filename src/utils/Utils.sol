// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {PackedUserOperation} from "../interfaces/PackedUserOperation.sol";

function calldataKeccak(bytes calldata data) pure returns (bytes32 ret) {
    assembly ("memory-safe") {
        let mem := mload(0x40)
        let len := data.length
        calldatacopy(mem, data.offset, len)
        ret := keccak256(mem, len)
    }
}

function getSender(PackedUserOperation calldata userOp) pure returns (address) {
    address data;
    //read sender from userOp, which is first userOp member (saves 800 gas...)
    assembly {
        data := calldataload(userOp)
    }
    return address(uint160(data));
}
