// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

struct OnchainCrossChainOrder {
    uint32 fillDeadline;
    bytes32 orderDataType;
    bytes orderData;
}

contract MockBridge {
    event Open(OnchainCrossChainOrder order);

    function open(OnchainCrossChainOrder calldata order) public {
        emit Open(order);
    }
}
