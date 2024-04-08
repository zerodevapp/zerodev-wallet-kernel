pragma solidity ^0.8.0;

import "forge-std/Script.sol";
import "src/Kernel.sol";
import "forge-std/console.sol";

import "src/factory/FactoryStaker.sol";
import "src/factory/KernelFactory.sol";

contract DeployDeterministic is Script {
    address constant DEPLOYER = 0x9775137314fE595c943712B0b336327dfa80aE8A;
    address constant ENTRYPOINT_0_7_ADDR = 0x0000000071727De22E5E9d8BAf0edAc6f37da032;

    address constant EXPECTED_STAKER = 0xd703aaE79538628d27099B8c4f621bE4CCd142d5;
    address constant EXPECTED_KERNEL = 0xe59cffb45AFFB215e3823F7D1a207a71C1aa09c3;

    function run() external {
        vm.startBroadcast(DEPLOYER);
        FactoryStaker staker = FactoryStaker(EXPECTED_STAKER);
        if(EXPECTED_STAKER.code.length == 0) {
            staker = new FactoryStaker{salt:0}(DEPLOYER);
            console.log("Factory Staker :", address(staker));
            require(address(staker) == EXPECTED_STAKER, "staker mismatch");
        }
        Kernel kernel = Kernel(payable(EXPECTED_KERNEL));
        if(EXPECTED_KERNEL.code.length == 0) {
            kernel = new Kernel{salt: 0}(IEntryPoint(payable(ENTRYPOINT_0_7_ADDR)));
            console.log("Kernel :", address(kernel));
            require(address(kernel) == EXPECTED_KERNEL, "kernel mismatch");
        }

        KernelFactory factory = new KernelFactory{salt:0}(address(kernel));
        console.log("Factory :", address(factory));

        staker.approveFactory(factory, true);
        console.log("Approved");
        vm.stopBroadcast();
    }
}
