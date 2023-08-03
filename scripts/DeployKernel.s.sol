pragma solidity ^0.8.0;

import "src/KernelFactory.sol";
import "forge-std/Script.sol";
import "forge-std/console.sol";
contract DeployKernel is Script {
    address DETERMINISTIC_DEPLOYER = 0x4e59b44847b379578588920cA78FbF26c0B4956C;
    address PREDICTED_ADDRESS = 0x4E4946298614FC299B50c947289F4aD0572CB9ce;
    bytes constant deployCallData = hex"000000000000000000000000000000000000000000000000000000000000000060a06040523480156200001157600080fd5b506040516200466d3803806200466d833981810160405281019062000037919062000136565b806040516200004690620000aa565b620000529190620001d3565b604051809103906000f0801580156200006f573d6000803e3d6000fd5b5073ffffffffffffffffffffffffffffffffffffffff1660808173ffffffffffffffffffffffffffffffffffffffff168152505050620001f0565b613527806200114683390190565b600080fd5b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b6000620000ea82620000bd565b9050919050565b6000620000fe82620000dd565b9050919050565b6200011081620000f1565b81146200011c57600080fd5b50565b600081519050620001308162000105565b92915050565b6000602082840312156200014f576200014e620000b8565b5b60006200015f848285016200011f565b91505092915050565b6000819050919050565b6000620001936200018d6200018784620000bd565b62000168565b620000bd565b9050919050565b6000620001a78262000172565b9050919050565b6000620001bb826200019a565b9050919050565b620001cd81620001ae565b82525050565b6000602082019050620001ea6000830184620001c2565b92915050565b608051610f26620002206000396000818160db0152818161015a0152818161028a01526103830152610f266000f3fe60806040523480156200001157600080fd5b5060043610620000465760003560e01c8063037637aa146200004b5780630d253d76146200006d5780635fbfb9cf14620000a3575b600080fd5b62000055620000d9565b604051620000649190620005a4565b60405180910390f35b6200008b600480360381019062000085919062000646565b620000fd565b6040516200009a91906200069e565b60405180910390f35b620000c16004803603810190620000bb919062000646565b6200022b565b604051620000d09190620006e0565b60405180910390f35b7f000000000000000000000000000000000000000000000000000000000000000081565b60008083836040516020016200011592919062000772565b60405160208183030381529060405280519060200120905062000222816040518060200162000144906200050b565b6020820181038252601f19601f820116604052507f0000000000000000000000000000000000000000000000000000000000000000876040516024016200018c91906200069e565b60405160208183030381529060405263c4d66de860e01b6020820180517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff8381831617835250505050604051602001620001e49291906200083c565b60405160208183030381529060405260405160200162000206929190620008b2565b60405160208183030381529060405280519060200120620004c9565b91505092915050565b60008083836040516020016200024392919062000772565b604051602081830303815290604052805190602001209050600062000352826040518060200162000274906200050b565b6020820181038252601f19601f820116604052507f000000000000000000000000000000000000000000000000000000000000000088604051602401620002bc91906200069e565b60405160208183030381529060405263c4d66de860e01b6020820180517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff8381831617835250505050604051602001620003149291906200083c565b60405160208183030381529060405260405160200162000336929190620008b2565b60405160208183030381529060405280519060200120620004c9565b905060008173ffffffffffffffffffffffffffffffffffffffff163b111562000380578092505050620004c3565b817f000000000000000000000000000000000000000000000000000000000000000063c4d66de860e01b87604051602401620003bd91906200069e565b604051602081830303815290604052907bffffffffffffffffffffffffffffffffffffffffffffffffffffffff19166020820180517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff838183161783525050505060405162000428906200050b565b620004359291906200083c565b8190604051809103906000f590508015801562000456573d6000803e3d6000fd5b5092508473ffffffffffffffffffffffffffffffffffffffff168373ffffffffffffffffffffffffffffffffffffffff167f33310a89c32d8cc00057ad6ef6274d2f8fe22389a992cf89983e09fc84f6cfff86604051620004b89190620008eb565b60405180910390a350505b92915050565b6000620004d8838330620004e0565b905092915050565b6000604051836040820152846020820152828152600b810160ff815360558120925050509392505050565b6105e8806200090983390190565b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b6000819050919050565b6000620005646200055e620005588462000519565b62000539565b62000519565b9050919050565b6000620005788262000543565b9050919050565b60006200058c826200056b565b9050919050565b6200059e816200057f565b82525050565b6000602082019050620005bb600083018462000593565b92915050565b600080fd5b6000620005d38262000519565b9050919050565b620005e581620005c6565b8114620005f157600080fd5b50565b6000813590506200060581620005da565b92915050565b6000819050919050565b62000620816200060b565b81146200062c57600080fd5b50565b600081359050620006408162000615565b92915050565b6000806040838503121562000660576200065f620005c1565b5b60006200067085828601620005f4565b925050602062000683858286016200062f565b9150509250929050565b6200069881620005c6565b82525050565b6000602082019050620006b560008301846200068d565b92915050565b6000620006c8826200056b565b9050919050565b620006da81620006bb565b82525050565b6000602082019050620006f76000830184620006cf565b92915050565b60008160601b9050919050565b60006200071782620006fd565b9050919050565b60006200072b826200070a565b9050919050565b620007476200074182620005c6565b6200071e565b82525050565b6000819050919050565b6200076c62000766826200060b565b6200074d565b82525050565b600062000780828562000732565b60148201915062000792828462000757565b6020820191508190509392505050565b600081519050919050565b600082825260208201905092915050565b60005b83811015620007de578082015181840152602081019050620007c1565b60008484015250505050565b6000601f19601f8301169050919050565b60006200080882620007a2565b620008148185620007ad565b935062000826818560208601620007be565b6200083181620007ea565b840191505092915050565b60006040820190506200085360008301856200068d565b8181036020830152620008678184620007fb565b90509392505050565b600081905092915050565b60006200088882620007a2565b62000894818562000870565b9350620008a6818560208601620007be565b80840191505092915050565b6000620008c082856200087b565b9150620008ce82846200087b565b91508190509392505050565b620008e5816200060b565b82525050565b6000602082019050620009026000830184620008da565b9291505056fe60806040526040516105e83803806105e883398181016040528101906100259190610351565b600073ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff1603610094576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161008b90610430565b60405180910390fd5b60007f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc60001b90508281556000825111156101765760008373ffffffffffffffffffffffffffffffffffffffff16836040516100f09190610497565b600060405180830381855af49150503d806000811461012b576040519150601f19603f3d011682016040523d82523d6000602084013e610130565b606091505b5050905080610174576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161016b90610520565b60405180910390fd5b505b505050610540565b6000604051905090565b600080fd5b600080fd5b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b60006101bd82610192565b9050919050565b6101cd816101b2565b81146101d857600080fd5b50565b6000815190506101ea816101c4565b92915050565b600080fd5b600080fd5b6000601f19601f8301169050919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b610243826101fa565b810181811067ffffffffffffffff821117156102625761026161020b565b5b80604052505050565b600061027561017e565b9050610281828261023a565b919050565b600067ffffffffffffffff8211156102a1576102a061020b565b5b6102aa826101fa565b9050602081019050919050565b60005b838110156102d55780820151818401526020810190506102ba565b60008484015250505050565b60006102f46102ef84610286565b61026b565b9050828152602081018484840111156103105761030f6101f5565b5b61031b8482856102b7565b509392505050565b600082601f830112610338576103376101f0565b5b81516103488482602086016102e1565b91505092915050565b6000806040838503121561036857610367610188565b5b6000610376858286016101db565b925050602083015167ffffffffffffffff8111156103975761039661018d565b5b6103a385828601610323565b9150509250929050565b600082825260208201905092915050565b7f4549503139363750726f78793a20696d706c656d656e746174696f6e2069732060008201527f746865207a65726f206164647265737300000000000000000000000000000000602082015250565b600061041a6030836103ad565b9150610425826103be565b604082019050919050565b600060208201905081810360008301526104498161040d565b9050919050565b600081519050919050565b600081905092915050565b600061047182610450565b61047b818561045b565b935061048b8185602086016102b7565b80840191505092915050565b60006104a38284610466565b915081905092915050565b7f4549503139363750726f78793a20636f6e7374727563746f722063616c6c206660008201527f61696c6564000000000000000000000000000000000000000000000000000000602082015250565b600061050a6025836103ad565b9150610515826104ae565b604082019050919050565b60006020820190508181036000830152610539816104fd565b9050919050565b609a8061054e6000396000f3fe60806040526000600c6033565b90503660008037600080366000845af43d6000803e8060008114602e573d6000f35b3d6000fd5b6000807f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc60001b905080549150509056fea2646970667358221220388bcbb27d5b065c1b785d1b94666d7f301b338574b92c716035a8fc03df3d4064736f6c63430008120033a2646970667358221220f50046c0d563594938691fabbaecaf185ed1de2d60d093c2816cf6a34a40c32a64736f6c634300081200336101606040523480156200001257600080fd5b5060405162003527380380620035278339818101604052810190620000389190620002e2565b806040518060400160405280600681526020017f4b65726e656c00000000000000000000000000000000000000000000000000008152506040518060400160405280600581526020017f302e302e3100000000000000000000000000000000000000000000000000000081525060008280519060200120905060008280519060200120905060007f8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f90508260e081815250508161010081815250504660a081815250506200010e818484620001e760201b60201c565b608081815250503073ffffffffffffffffffffffffffffffffffffffff1660c08173ffffffffffffffffffffffffffffffffffffffff168152505080610120818152505050505050508073ffffffffffffffffffffffffffffffffffffffff166101408173ffffffffffffffffffffffffffffffffffffffff168152505060016200019e6200022360201b60201c565b60000160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550505062000422565b60008383834630604051602001620002049594939291906200035b565b6040516020818303038152906040528051906020012090509392505050565b60008060017f439ffe7df606b78489639bc0b827913bd09e1246fa6802968a5b3694c53e0dd960001c620002589190620003e7565b60001b90508091505090565b600080fd5b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b6000620002968262000269565b9050919050565b6000620002aa8262000289565b9050919050565b620002bc816200029d565b8114620002c857600080fd5b50565b600081519050620002dc81620002b1565b92915050565b600060208284031215620002fb57620002fa62000264565b5b60006200030b84828501620002cb565b91505092915050565b6000819050919050565b620003298162000314565b82525050565b6000819050919050565b62000344816200032f565b82525050565b620003558162000289565b82525050565b600060a0820190506200037260008301886200031e565b6200038160208301876200031e565b6200039060408301866200031e565b6200039f606083018562000339565b620003ae60808301846200034a565b9695505050505050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b6000620003f4826200032f565b915062000401836200032f565b92508282039050818111156200041c576200041b620003b8565b5b92915050565b60805160a05160c05160e051610100516101205161014051613080620004a76000396000818161057a0152818161071301528181610b1501528181610c2401528181610e0b01528181610f2f0152610fe701526000611800015260006118420152600061182101526000611756015260006117ac015260006117d501526130806000f3fe6080604052600436106100f75760003560e01c8063940d3c601161008a578063d087d28811610059578063d087d2881461035b578063f23a6e6114610386578063f2fde38b146103c3578063f333df55146103ec576100fe565b8063940d3c60146102a1578063b0d691fe146102ca578063bc197c81146102f5578063c4d66de814610332576100fe565b80633a871cdd116100c65780633a871cdd146101d15780633e1b08121461020e57806354fd4d501461024b578063893d20e814610276576100fe565b806306fdde0314610103578063150b7a021461012e5780631626ba7e1461016b5780633659cfe6146101a8576100fe565b366100fe57005b600080fd5b34801561010f57600080fd5b50610118610415565b6040516101259190611a4b565b60405180910390f35b34801561013a57600080fd5b5061015560048036038101906101509190611b7a565b61044e565b6040516101629190611c3d565b60405180910390f35b34801561017757600080fd5b50610192600480360381019061018d9190611dbe565b610463565b60405161019f9190611c3d565b60405180910390f35b3480156101b457600080fd5b506101cf60048036038101906101ca9190611e1a565b610578565b005b3480156101dd57600080fd5b506101f860048036038101906101f39190611e6c565b61070f565b6040516102059190611eea565b60405180910390f35b34801561021a57600080fd5b5061023560048036038101906102309190611f55565b610b11565b6040516102429190611eea565b60405180910390f35b34801561025757600080fd5b50610260610bb6565b60405161026d9190611a4b565b60405180910390f35b34801561028257600080fd5b5061028b610bef565b6040516102989190611f91565b60405180910390f35b3480156102ad57600080fd5b506102c860048036038101906102c39190611fd1565b610c22565b005b3480156102d657600080fd5b506102df610e09565b6040516102ec91906120b8565b60405180910390f35b34801561030157600080fd5b5061031c60048036038101906103179190612129565b610e2d565b6040516103299190611c3d565b60405180910390f35b34801561033e57600080fd5b5061035960048036038101906103549190611e1a565b610e45565b005b34801561036757600080fd5b50610370610f2b565b60405161037d9190611eea565b60405180910390f35b34801561039257600080fd5b506103ad60048036038101906103a89190612205565b610fcf565b6040516103ba9190611c3d565b60405180910390f35b3480156103cf57600080fd5b506103ea60048036038101906103e59190611e1a565b610fe5565b005b3480156103f857600080fd5b50610413600480360381019061040e919061229f565b611157565b005b6040518060400160405280600681526020017f4b65726e656c000000000000000000000000000000000000000000000000000081525081565b600063150b7a0260e01b905095945050505050565b60008061046e6111f7565b905061047a8484611236565b73ffffffffffffffffffffffffffffffffffffffff168160000160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16036104e057631626ba7e60e01b915050610572565b60006104eb8561125d565b905060006104f98286611236565b90508073ffffffffffffffffffffffffffffffffffffffff168360000160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff160361056457631626ba7e60e01b9350505050610572565b63ffffffff60e01b93505050505b92915050565b7f000000000000000000000000000000000000000000000000000000000000000073ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff16148061062857506105d56111f7565b60000160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff16145b8061065e57503073ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff16145b61069d576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161069490612371565b60405180910390fd5b60007f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc60001b90508181558173ffffffffffffffffffffffffffffffffffffffff167fbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b60405160405180910390a25050565b60007f000000000000000000000000000000000000000000000000000000000000000073ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff161461079f576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610796906123dd565b60405180910390fd5b6041848061014001906107b2919061240c565b9050036107ca576107c3848461128d565b9050610a8e565b6061848061014001906107dd919061240c565b90501115610a5b576000848061014001906107f8919061240c565b60009060149261080a93929190612479565b9061081591906124f8565b60601c905060008580610140019061082d919061240c565b601490601a9261083f93929190612479565b9061084a9190612583565b60d01c9050600086806101400190610862919061240c565b601a9060209261087493929190612479565b9061087f9190612583565b60d01c9050600087806101400190610897919061240c565b6020906061926108a993929190612479565b8080601f016020809104026020016040519081016040528093929190818152602001838380828437600081840152601f19601f820116905080830192505050505050509050600088806101400190610901919061240c565b606190809261091293929190612479565b81019061091f91906125e2565b50905060006109827f4584533bad8bbd8aa77024a548a56acb8d2807847381ce1b3364745ca396b2e3878787868051906020012060405160200161096795949392919061268a565b6040516020818303038152906040528051906020012061142e565b905060006109908285611236565b90508073ffffffffffffffffffffffffffffffffffffffff166109b16111f7565b60000160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1614610a00576001975050505050505050610b0a565b6000610a0e888d8d8d611448565b9050600081806020019051810190610a269190612715565b905080610a3f5760019950505050505050505050610b0a565b610a4b811589896114f4565b9950505050505050505050610a8d565b6040517f4be6321b00000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b5b6000821115610b095760003373ffffffffffffffffffffffffffffffffffffffff1683604051610abd90612773565b60006040518083038185875af1925050503d8060008114610afa576040519150601f19603f3d011682016040523d82523d6000602084013e610aff565b606091505b5050905050610b0a565b5b9392505050565b60007f000000000000000000000000000000000000000000000000000000000000000073ffffffffffffffffffffffffffffffffffffffff166335567e1a30846040518363ffffffff1660e01b8152600401610b6e929190612797565b602060405180830381865afa158015610b8b573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190610baf91906127d5565b9050919050565b6040518060400160405280600581526020017f302e302e3100000000000000000000000000000000000000000000000000000081525081565b6000610bf96111f7565b60000160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff16905090565b7f000000000000000000000000000000000000000000000000000000000000000073ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff161480610cd25750610c7f6111f7565b60000160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff16145b610d11576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610d0890612874565b60405180910390fd5b60006060600180811115610d2857610d27612894565b5b836001811115610d3b57610d3a612894565b5b03610d9b57610d8e8786868080601f016020809104026020016040519081016040528093929190818152602001838380828437600081840152601f19601f8201169050808301925050505050505061152d565b8092508193505050610df3565b610dea878787878080601f016020809104026020016040519081016040528093929190818152602001838380828437600081840152601f19601f82011690508083019250505050505050611563565b80925081935050505b81610e0057805160208201fd5b50505050505050565b7f000000000000000000000000000000000000000000000000000000000000000081565b600063bc197c8160e01b905098975050505050505050565b6000610e4f6111f7565b9050600073ffffffffffffffffffffffffffffffffffffffff168160000160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1614610ee4576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610edb9061290f565b60405180910390fd5b818160000160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055505050565b60007f000000000000000000000000000000000000000000000000000000000000000073ffffffffffffffffffffffffffffffffffffffff166335567e1a3060006040518363ffffffff1660e01b8152600401610f8992919061296a565b602060405180830381865afa158015610fa6573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190610fca91906127d5565b905090565b600063f23a6e6160e01b90509695505050505050565b7f000000000000000000000000000000000000000000000000000000000000000073ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff16148061109557506110426111f7565b60000160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff16145b806110cb57503073ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff16145b61110a576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161110190612371565b60405180910390fd5b806111136111f7565b60000160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555050565b6000806111a88585858080601f016020809104026020016040519081016040528093929190818152602001838380828437600081840152601f19601f8201169050808301925050505050505061152d565b9150915081156111ef57806040517fa52b21690000000000000000000000000000000000000000000000000000000081526004016111e691906129e8565b60405180910390fd5b805160208201fd5b60008060017f439ffe7df606b78489639bc0b827913bd09e1246fa6802968a5b3694c53e0dd960001c61122a9190612a39565b60001b90508091505090565b6000806000611245858561159b565b91509150611252816115ec565b819250505092915050565b6000816040516020016112709190612ae5565b604051602081830303815290604052805190602001209050919050565b6000806112986111f7565b90506112f783858061014001906112af919061240c565b8080601f016020809104026020016040519081016040528093929190818152602001838380828437600081840152601f19601f82011690508083019250505050505050611236565b73ffffffffffffffffffffffffffffffffffffffff168160000160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16036113535750611428565b600061135e8461125d565b905060006113bf8287806101400190611377919061240c565b8080601f016020809104026020016040519081016040528093929190818152602001838380828437600081840152601f19601f82011690508083019250505050505050611236565b90508073ffffffffffffffffffffffffffffffffffffffff168360000160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16146114245760019350505050611428565b5050505b92915050565b600061144161143b611752565b8361186c565b9050919050565b60606000639e2045ce60e01b85858560405160240161146993929190612d6b565b604051602081830303815290604052907bffffffffffffffffffffffffffffffffffffffffffffffffffffffff19166020820180517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff838183161783525050505090506000806114d5888461152d565b91509150816114e657805160208201fd5b809350505050949350505050565b600060d08265ffffffffffff16901b60a08465ffffffffffff16901b8561151c57600061151f565b60015b60ff16171790509392505050565b60006060600080845160208601875af491503d604051602082018101604052818152816000602083013e80925050509250929050565b6000606060008084516020860187895af191503d604051602082018101604052818152816000602083013e8092505050935093915050565b60008060418351036115dc5760008060006020860151925060408601519150606086015160001a90506115d08782858561189f565b945094505050506115e5565b60006002915091505b9250929050565b60006004811115611600576115ff612894565b5b81600481111561161357611612612894565b5b031561174f576001600481111561162d5761162c612894565b5b8160048111156116405761163f612894565b5b03611680576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161167790612df5565b60405180910390fd5b6002600481111561169457611693612894565b5b8160048111156116a7576116a6612894565b5b036116e7576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016116de90612e61565b60405180910390fd5b600360048111156116fb576116fa612894565b5b81600481111561170e5761170d612894565b5b0361174e576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161174590612ef3565b60405180910390fd5b5b50565b60007f000000000000000000000000000000000000000000000000000000000000000073ffffffffffffffffffffffffffffffffffffffff163073ffffffffffffffffffffffffffffffffffffffff161480156117ce57507f000000000000000000000000000000000000000000000000000000000000000046145b156117fb577f00000000000000000000000000000000000000000000000000000000000000009050611869565b6118667f00000000000000000000000000000000000000000000000000000000000000007f00000000000000000000000000000000000000000000000000000000000000007f0000000000000000000000000000000000000000000000000000000000000000611981565b90505b90565b60008282604051602001611881929190612f5f565b60405160208183030381529060405280519060200120905092915050565b6000807f7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a08360001c11156118da576000600391509150611978565b6000600187878787604051600081526020016040526040516118ff9493929190612fb2565b6020604051602081039080840390855afa158015611921573d6000803e3d6000fd5b505050602060405103519050600073ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff160361196f57600060019250925050611978565b80600092509250505b94509492505050565b6000838383463060405160200161199c959493929190612ff7565b6040516020818303038152906040528051906020012090509392505050565b600081519050919050565b600082825260208201905092915050565b60005b838110156119f55780820151818401526020810190506119da565b60008484015250505050565b6000601f19601f8301169050919050565b6000611a1d826119bb565b611a2781856119c6565b9350611a378185602086016119d7565b611a4081611a01565b840191505092915050565b60006020820190508181036000830152611a658184611a12565b905092915050565b6000604051905090565b600080fd5b600080fd5b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b6000611aac82611a81565b9050919050565b611abc81611aa1565b8114611ac757600080fd5b50565b600081359050611ad981611ab3565b92915050565b6000819050919050565b611af281611adf565b8114611afd57600080fd5b50565b600081359050611b0f81611ae9565b92915050565b600080fd5b600080fd5b600080fd5b60008083601f840112611b3a57611b39611b15565b5b8235905067ffffffffffffffff811115611b5757611b56611b1a565b5b602083019150836001820283011115611b7357611b72611b1f565b5b9250929050565b600080600080600060808688031215611b9657611b95611a77565b5b6000611ba488828901611aca565b9550506020611bb588828901611aca565b9450506040611bc688828901611b00565b935050606086013567ffffffffffffffff811115611be757611be6611a7c565b5b611bf388828901611b24565b92509250509295509295909350565b60007fffffffff0000000000000000000000000000000000000000000000000000000082169050919050565b611c3781611c02565b82525050565b6000602082019050611c526000830184611c2e565b92915050565b6000819050919050565b611c6b81611c58565b8114611c7657600080fd5b50565b600081359050611c8881611c62565b92915050565b600080fd5b7f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b611ccb82611a01565b810181811067ffffffffffffffff82111715611cea57611ce9611c93565b5b80604052505050565b6000611cfd611a6d565b9050611d098282611cc2565b919050565b600067ffffffffffffffff821115611d2957611d28611c93565b5b611d3282611a01565b9050602081019050919050565b82818337600083830152505050565b6000611d61611d5c84611d0e565b611cf3565b905082815260208101848484011115611d7d57611d7c611c8e565b5b611d88848285611d3f565b509392505050565b600082601f830112611da557611da4611b15565b5b8135611db5848260208601611d4e565b91505092915050565b60008060408385031215611dd557611dd4611a77565b5b6000611de385828601611c79565b925050602083013567ffffffffffffffff811115611e0457611e03611a7c565b5b611e1085828601611d90565b9150509250929050565b600060208284031215611e3057611e2f611a77565b5b6000611e3e84828501611aca565b91505092915050565b600080fd5b60006101608284031215611e6357611e62611e47565b5b81905092915050565b600080600060608486031215611e8557611e84611a77565b5b600084013567ffffffffffffffff811115611ea357611ea2611a7c565b5b611eaf86828701611e4c565b9350506020611ec086828701611c79565b9250506040611ed186828701611b00565b9150509250925092565b611ee481611adf565b82525050565b6000602082019050611eff6000830184611edb565b92915050565b600077ffffffffffffffffffffffffffffffffffffffffffffffff82169050919050565b611f3281611f05565b8114611f3d57600080fd5b50565b600081359050611f4f81611f29565b92915050565b600060208284031215611f6b57611f6a611a77565b5b6000611f7984828501611f40565b91505092915050565b611f8b81611aa1565b82525050565b6000602082019050611fa66000830184611f82565b92915050565b60028110611fb957600080fd5b50565b600081359050611fcb81611fac565b92915050565b600080600080600060808688031215611fed57611fec611a77565b5b6000611ffb88828901611aca565b955050602061200c88828901611b00565b945050604086013567ffffffffffffffff81111561202d5761202c611a7c565b5b61203988828901611b24565b9350935050606061204c88828901611fbc565b9150509295509295909350565b6000819050919050565b600061207e61207961207484611a81565b612059565b611a81565b9050919050565b600061209082612063565b9050919050565b60006120a282612085565b9050919050565b6120b281612097565b82525050565b60006020820190506120cd60008301846120a9565b92915050565b60008083601f8401126120e9576120e8611b15565b5b8235905067ffffffffffffffff81111561210657612105611b1a565b5b60208301915083602082028301111561212257612121611b1f565b5b9250929050565b60008060008060008060008060a0898b03121561214957612148611a77565b5b60006121578b828c01611aca565b98505060206121688b828c01611aca565b975050604089013567ffffffffffffffff81111561218957612188611a7c565b5b6121958b828c016120d3565b9650965050606089013567ffffffffffffffff8111156121b8576121b7611a7c565b5b6121c48b828c016120d3565b9450945050608089013567ffffffffffffffff8111156121e7576121e6611a7c565b5b6121f38b828c01611b24565b92509250509295985092959890939650565b60008060008060008060a0878903121561222257612221611a77565b5b600061223089828a01611aca565b965050602061224189828a01611aca565b955050604061225289828a01611b00565b945050606061226389828a01611b00565b935050608087013567ffffffffffffffff81111561228457612283611a7c565b5b61229089828a01611b24565b92509250509295509295509295565b6000806000604084860312156122b8576122b7611a77565b5b60006122c686828701611aca565b935050602084013567ffffffffffffffff8111156122e7576122e6611a7c565b5b6122f386828701611b24565b92509250509250925092565b7f6163636f756e743a206e6f742066726f6d20656e747279706f696e74206f722060008201527f6f776e6572206f722073656c6600000000000000000000000000000000000000602082015250565b600061235b602d836119c6565b9150612366826122ff565b604082019050919050565b6000602082019050818103600083015261238a8161234e565b9050919050565b7f6163636f756e743a206e6f742066726f6d20656e747279506f696e7400000000600082015250565b60006123c7601c836119c6565b91506123d282612391565b602082019050919050565b600060208201905081810360008301526123f6816123ba565b9050919050565b600080fd5b600080fd5b600080fd5b60008083356001602003843603038112612429576124286123fd565b5b80840192508235915067ffffffffffffffff82111561244b5761244a612402565b5b60208301925060018202360383131561246757612466612407565b5b509250929050565b600080fd5b600080fd5b6000808585111561248d5761248c61246f565b5b8386111561249e5761249d612474565b5b6001850283019150848603905094509492505050565b600082905092915050565b60007fffffffffffffffffffffffffffffffffffffffff00000000000000000000000082169050919050565b600082821b905092915050565b600061250483836124b4565b8261250f81356124bf565b9250601482101561254f5761254a7fffffffffffffffffffffffffffffffffffffffff000000000000000000000000836014036008026124eb565b831692505b505092915050565b60007fffffffffffff000000000000000000000000000000000000000000000000000082169050919050565b600061258f83836124b4565b8261259a8135612557565b925060068210156125da576125d57fffffffffffff0000000000000000000000000000000000000000000000000000836006036008026124eb565b831692505b505092915050565b600080604083850312156125f9576125f8611a77565b5b600083013567ffffffffffffffff81111561261757612616611a7c565b5b61262385828601611d90565b925050602083013567ffffffffffffffff81111561264457612643611a7c565b5b61265085828601611d90565b9150509250929050565b61266381611c58565b82525050565b600065ffffffffffff82169050919050565b61268481612669565b82525050565b600060a08201905061269f600083018861265a565b6126ac6020830187611f82565b6126b9604083018661267b565b6126c6606083018561267b565b6126d3608083018461265a565b9695505050505050565b60008115159050919050565b6126f2816126dd565b81146126fd57600080fd5b50565b60008151905061270f816126e9565b92915050565b60006020828403121561272b5761272a611a77565b5b600061273984828501612700565b91505092915050565b600081905092915050565b50565b600061275d600083612742565b91506127688261274d565b600082019050919050565b600061277e82612750565b9150819050919050565b61279181611f05565b82525050565b60006040820190506127ac6000830185611f82565b6127b96020830184612788565b9392505050565b6000815190506127cf81611ae9565b92915050565b6000602082840312156127eb576127ea611a77565b5b60006127f9848285016127c0565b91505092915050565b7f6163636f756e743a206e6f742066726f6d20656e747279706f696e74206f722060008201527f6f776e6572000000000000000000000000000000000000000000000000000000602082015250565b600061285e6025836119c6565b915061286982612802565b604082019050919050565b6000602082019050818103600083015261288d81612851565b9050919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052602160045260246000fd5b7f6163636f756e743a20616c726561647920696e697469616c697a656400000000600082015250565b60006128f9601c836119c6565b9150612904826128c3565b602082019050919050565b60006020820190508181036000830152612928816128ec565b9050919050565b6000819050919050565b600061295461294f61294a8461292f565b612059565b611f05565b9050919050565b61296481612939565b82525050565b600060408201905061297f6000830185611f82565b61298c602083018461295b565b9392505050565b600081519050919050565b600082825260208201905092915050565b60006129ba82612993565b6129c4818561299e565b93506129d48185602086016119d7565b6129dd81611a01565b840191505092915050565b60006020820190508181036000830152612a0281846129af565b905092915050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b6000612a4482611adf565b9150612a4f83611adf565b9250828203905081811115612a6757612a66612a0a565b5b92915050565b600081905092915050565b7f19457468657265756d205369676e6564204d6573736167653a0a333200000000600082015250565b6000612aae601c83612a6d565b9150612ab982612a78565b601c82019050919050565b6000819050919050565b612adf612ada82611c58565b612ac4565b82525050565b6000612af082612aa1565b9150612afc8284612ace565b60208201915081905092915050565b6000612b1a6020840184611aca565b905092915050565b612b2b81611aa1565b82525050565b6000612b406020840184611b00565b905092915050565b612b5181611adf565b82525050565b600080fd5b600080fd5b600080fd5b60008083356001602003843603038112612b8357612b82612b61565b5b83810192508235915060208301925067ffffffffffffffff821115612bab57612baa612b57565b5b600182023603831315612bc157612bc0612b5c565b5b509250929050565b600082825260208201905092915050565b6000612be68385612bc9565b9350612bf3838584611d3f565b612bfc83611a01565b840190509392505050565b60006101608301612c1b6000840184612b0b565b612c286000860182612b22565b50612c366020840184612b31565b612c436020860182612b48565b50612c516040840184612b66565b8583036040870152612c64838284612bda565b92505050612c756060840184612b66565b8583036060870152612c88838284612bda565b92505050612c996080840184612b31565b612ca66080860182612b48565b50612cb460a0840184612b31565b612cc160a0860182612b48565b50612ccf60c0840184612b31565b612cdc60c0860182612b48565b50612cea60e0840184612b31565b612cf760e0860182612b48565b50612d06610100840184612b31565b612d14610100860182612b48565b50612d23610120840184612b66565b858303610120870152612d37838284612bda565b92505050612d49610140840184612b66565b858303610140870152612d5d838284612bda565b925050508091505092915050565b60006060820190508181036000830152612d858186612c07565b9050612d94602083018561265a565b612da16040830184611edb565b949350505050565b7f45434453413a20696e76616c6964207369676e61747572650000000000000000600082015250565b6000612ddf6018836119c6565b9150612dea82612da9565b602082019050919050565b60006020820190508181036000830152612e0e81612dd2565b9050919050565b7f45434453413a20696e76616c6964207369676e6174757265206c656e67746800600082015250565b6000612e4b601f836119c6565b9150612e5682612e15565b602082019050919050565b60006020820190508181036000830152612e7a81612e3e565b9050919050565b7f45434453413a20696e76616c6964207369676e6174757265202773272076616c60008201527f7565000000000000000000000000000000000000000000000000000000000000602082015250565b6000612edd6022836119c6565b9150612ee882612e81565b604082019050919050565b60006020820190508181036000830152612f0c81612ed0565b9050919050565b7f1901000000000000000000000000000000000000000000000000000000000000600082015250565b6000612f49600283612a6d565b9150612f5482612f13565b600282019050919050565b6000612f6a82612f3c565b9150612f768285612ace565b602082019150612f868284612ace565b6020820191508190509392505050565b600060ff82169050919050565b612fac81612f96565b82525050565b6000608082019050612fc7600083018761265a565b612fd46020830186612fa3565b612fe1604083018561265a565b612fee606083018461265a565b95945050505050565b600060a08201905061300c600083018861265a565b613019602083018761265a565b613026604083018661265a565b6130336060830185611edb565b6130406080830184611f82565b969550505050505056fea264697066735822122032ca1cf88a7b31318141bd230c1cabd5f99c4503ed694966da441ea9decb738c64736f6c634300081200330000000000000000000000005ff137d4b0fdcd49dca30c7cf57e578a026d2789";
    function run() public {
        uint256 key = vm.envUint("DEPLOYER_PRIVATE_KEY");
        vm.startBroadcast(key);
        (bool success, bytes memory ret) = DETERMINISTIC_DEPLOYER.call(deployCallData);
        if(!success) {
            console.log("deploy failed");
            revert(string(ret));
        }
        console.log("ret length %s", ret.length);
        console.logBytes(ret);
        address addr = address(uint160(bytes20(ret)));
        require(addr == PREDICTED_ADDRESS, "address mismatch");
        vm.stopBroadcast();
    }
}

