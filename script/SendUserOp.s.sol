pragma solidity ^0.8.0;

import "forge-std/Script.sol";
import "../src/Kernel.sol";
import "../src/factory/KernelFactory.sol";
import "../src/factory/FactoryStaker.sol";
import "../src/validator/ECDSAValidator.sol";

contract SendUserOp is Script {
    IEntryPoint entrypoint;
    FactoryStaker staker;
    KernelFactory factory;
    address payable owner;
    uint256 ownerKey;
    ECDSAValidator ecdsaValidator;
    address constant DEPLOYER = 0x9775137314fE595c943712B0b336327dfa80aE8A;

    function run() public {
        entrypoint = IEntryPoint(0x0000000071727De22E5E9d8BAf0edAc6f37da032);
        staker = FactoryStaker(0xd703aaE79538628d27099B8c4f621bE4CCd142d5);
        factory = KernelFactory(0xaac5D4240AF87249B3f71BC8E4A2cae074A3E419);
        ecdsaValidator = ECDSAValidator(0x845ADb2C711129d4f3966735eD98a9F09fC4cE57);
        owner = payable(address(0x328809Bc894f92807417D2dAD6b7C998c1aFdac6));
        ownerKey = 70564938991660933374592024341600875602376452319261984317470407481576058979585;
        Kernel kernel = Kernel(payable(factory.getAddress(initData(), bytes32(0))));
        PackedUserOperation memory op = _prepareUserOp(
            kernel,
            encodeExecute(owner, 1, hex"")
        );
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;
        
        vm.startBroadcast(DEPLOYER);
        (bool success, ) = address(kernel).call{value : 3000000}(hex"");
        require(success);
        entrypoint.handleOps(ops, owner);
    }
    
    function encodeExecute(address _to, uint256 _amount, bytes memory _data) internal view returns (bytes memory) {
        return abi.encodeWithSelector(
            Kernel.execute.selector, ExecLib.encodeSimpleSingle(), ExecLib.encodeSingle(_to, _amount, _data)
        );
    }

    function _prepareUserOp(
        Kernel kernel,
        bytes memory callData
    ) internal returns (PackedUserOperation memory op) {
        op = PackedUserOperation({
            sender: address(kernel),
            nonce: entrypoint.getNonce(address(kernel), 0),
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
        op.signature = _signUserOp(op);
    }
    
    function initData() internal view returns (bytes memory) {
        return abi.encodeWithSelector(
            Kernel.initialize.selector,
            ValidatorLib.validatorToIdentifier(ecdsaValidator),
            IHook(address(0)),
            abi.encodePacked(owner),
            hex"",
            new bytes[](0)
        );
    }
    
    function _signUserOp(PackedUserOperation memory op)
        internal
        virtual
        returns (bytes memory data)
    {
        return _rootSignUserOp(op);
    }
    
    function _rootSignUserOp(PackedUserOperation memory op) internal virtual returns (bytes memory) {
        bytes32 hash = entrypoint.getUserOpHash(op);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, ECDSA.toEthSignedMessageHash(hash));
        return abi.encodePacked(r, s, v);
    }

}
