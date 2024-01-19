pragma solidity ^0.8.0;

import "./DeterministicDeploy.s.sol";

library SessionKeyDeploy {
    address constant EXPECTED_SESSIONKEY_ADDRESS = 0xB8E3c4bEaACAd06f6092793012DA4a8cB23D6123;
    bytes constant SESSIONKEY_CODE =
        hex"0000000000000000000000000000000000000000000000000000000000000000608080604052346100165761156e908161001c8239f35b600080fdfe60806040908082526004908136101561001757600080fd5b600092833560e01c9182630c9595561461034d57508163333daf921461031a5781633a871cdd146102d657816346585db21461027d57816352721fdd146102005781637ecebe00146101b8578382638fc925aa1461010b575081639ea9bd59146100bd575063dbba225d1461008b57600080fd5b346100b95760203660031901126100b957356001600160801b03811681036100b9576100b6906105d7565b80f35b5080fd5b905082346101085781600319360112610108576100d8610533565b50602435906001600160401b03821161010857506100f990369084016104eb565b50505163d623472560e01b8152fd5b80fd5b8091846020600319360112610170578035906001600160401b0382116101b357610137913691016104eb565b9091906014810361017457601411610170576002913560601c835260016020528083203384526020528220828155826001820155015580f35b5050fd5b9192506010820361019457506010116100b9576100b6903560801c6105d7565b6100b692506001600160801b03915033845283602052832054166105d7565b505050fd5b8390346100b95760203660031901126100b9579081906001600160a01b036101de610533565b1681528060205220548151906001600160801b038116825260801c6020820152f35b8390346100b957806003193601126100b9578060a09261021e610533565b61022661051d565b90600180871b03809116835260016020528383209116825260205220908154916002600182015491015491805193845265ffffffffffff80831660208601528260301c169084015260601c60608301526080820152f35b919050346102d257816003193601126102d25791819261029b61051d565b9035825260026020528282209060018060a01b03168252602052205481519065ffffffffffff90818116835260301c166020820152f35b8280fd5b91905060031992606084360112610108578135936001600160401b0385116100b95761016090853603011261010857506020926103139101610934565b9051908152f35b90508234610108578160031936011261010857602435906001600160401b03821161010857506100f990369084016104eb565b8492509060203660031901126102d2576001600160401b039184358381116104e35761037c90369087016104eb565b806014116104e757806034116104e75780603a116104e7578084116104e757806054116104e7576074116104e35760548101359360a08301908111838210176104d0579060029184526014810135835260208301603482013560d01c815284840190603a83013560d01c825261046160608601918785013560601c835260808701948986523560601c8a526001602052878a20338b52602052878a2096518755600187019365ffffffffffff8092511665ffffffffffff198654161785555116839065ffffffffffff60301b82549160301b169065ffffffffffff60301b1916179055565b516bffffffffffffffffffffffff82549181199060601b16911617905551910155826020528220908154916001600160801b038084168181146104bd576100b69596506001011680936001600160801b03191617905514610580565b634e487b7160e01b865260118752602486fd5b634e487b7160e01b865260418752602486fd5b8480fd5b8580fd5b9181601f84011215610518578235916001600160401b038311610518576020838186019501011161051857565b600080fd5b602435906001600160a01b038216820361051857565b600435906001600160a01b038216820361051857565b90601f801991011681019081106001600160401b0382111761056a57604052565b634e487b7160e01b600052604160045260246000fd5b1561058757565b60405162461bcd60e51b815260206004820152602260248201527f53657373696f6e4b657956616c696461746f723a20696e76616c6964206e6f6e604482015261636560f01b6064820152608490fd5b600033815280602052604080822054916105ff6001600160801b0385169360801c8411610580565b3381528060205220916001600160801b03199060801b16179055565b903590601e198136030182121561051857018035906001600160401b0382116105185760200191813603831361051857565b356001600160a01b03811681036105185790565b1561066857565b60405162461bcd60e51b8152602060048201526024808201527f53657373696f6e4b657956616c696461746f723a20746172676574206d69736d6044820152630c2e8c6d60e31b6064820152608490fd5b156106c057565b60405162461bcd60e51b815260206004820152602960248201527f53657373696f6e4b657956616c696461746f723a2076616c7565206c696d697460448201526808195e18d95959195960ba1b6064820152608490fd5b1561071e57565b60405162461bcd60e51b815260206004820152603360248201527f53657373696f6e4b657956616c696461746f723a207065726d697373696f6e206044820152721d995c9a599a58d85d1a5bdb8819985a5b1959606a1b6064820152608490fd5b3563ffffffff811681036105185790565b359065ffffffffffff8216820361051857565b602091828252610120820190803563ffffffff81168091036105185784840152808401356001600160a01b038116949085900361051857604094858501528482013563ffffffff60e01b811680910361051857606090818601528083013560808601526080830135601e1984360301811215610518578301918083359301966001600160401b03841161051857828402360388136105185792919082610100968760a08a01525261014087019793600080925b8584106108a3575050505050505061089c60e065ffffffffffff928361087e60a08301610790565b1660c08701528361089160c08301610790565b168287015201610790565b1691015290565b909192939495998a358152818b013560068110156108da57828201528a840135848201528501998501959493600101929190610856565b8380fd5b9092916001600160401b03841161056a578360051b604051926020809461090782850182610549565b809781520191810192831161051857905b8282106109255750505050565b81358152908301908301610918565b6101408101610943818361061b565b601411610518573560601c90600082815260019360209085825260408084203385528352808420936002850180548286528383205460801c1015610d0b578886019687548060601c8b8114600014610c8757506109a461012087018761061b565b905015610c34575b875415610c10575060608501926109c3848761061b565b6004939193116100b95782356001600160e01b031916635194544760e01b8103610b7057506109f2908761061b565b6055959195116100b9576055850135850190605582019560758101350197610a1a828261061b565b6024116104e357610a53929190610a4e9060106001600160a01b03610a416075890161064d565b1691013560601c14610661565b61061b565b6044939193116101085750610a9685610ae994610a82610acc9795602460b5610a9b97013591013511156106b9565b604481013501602460048201359101611388565b610717565b54610aa58461077f565b855188810192835260e09190911b6001600160e01b03191660208301529283906024830190565b0392610ae0601f1994858101835282610549565b51902083610ed8565b96549465ffffffffffff9687871680898b1610610b66575b50610b2f610b4393610b4897969593610b2393549651938491820195866107a3565b03908101835282610549565b5190209236906075605582013591016108de565b610d64565b15610b5f57610b5c945060301c1691610dbb565b90565b5050505090565b9850610b2f610b01565b94509450949650945050631a7e6adf60e19896981b14600014610c0657610b97818561061b565b6055116102d25790816055610baf930135019461061b565b605592919211610108575090816075610be19493013501916075605584013593019160756055830135920190876110f7565b919091610bff575065ffffffffffff610b5c935460301c1691610dbb565b9250505090565b5050505091505090565b98975050505050505050610b5c925065ffffffffffff808360301c16921690610dbb565b845162461bcd60e51b815260048101889052602660248201527f53657373696f6e4b657956616c696461746f723a207061796d6173746572206e6044820152651bdd081cd95d60d21b6064820152608490fd5b80610c93575b506109ac565b610ca161012088018861061b565b6014116104e7573560601c03610cb75738610c8d565b845162461bcd60e51b815260048101889052602760248201527f53657373696f6e4b657956616c696461746f723a207061796d6173746572206d6044820152660d2e6dac2e8c6d60cb1b6064820152608490fd5b825162461bcd60e51b815260048101869052602c60248201527f53657373696f6e4b657956616c696461746f723a2073657373696f6e206b657960448201526b081b9bdd08195b98589b195960a21b6064820152608490fd5b919091805180610d75575b50501490565b91906020908180820191600595861b0101925b81518111851b90815282825191185281604060002091019383851015610daf579390610d88565b50925050503880610d6f565b919091600435610144810135016024356020526000907b19457468657265756d205369676e6564204d6573736167653a0a33328252603c6004206040908151608081018181106001600160401b03821117610eb15783526041815260208101933660798201116104e75785604160209486600195836038608097018b3784606182015281519981519386526060820151861a89525182520151606052145afa51923d15610ea457606052526001600160a01b03908116911603610e9d5760d09190911b6001600160d01b03191660a09190911b65ffffffffffff60a01b161790565b5050600190565b638baa579f90526004601cfd5b634e487b7160e01b86526041600452602486fd5b3565ffffffffffff811681036105185790565b9065ffffffffffff60a0830160c0840182610ef282610ec5565b16610ff15750610f0360e091610ec5565b935b019181610f1184610ec5565b16610f1d575b50505090565b60009081526002602052604081203382526020526040812090600183835460301c160190838211610fdd575081546bffffffffffff000000000000191660309190911b65ffffffffffff60301b16178155610f7f9082905460301c1692610ec5565b1610610f8d57388080610f17565b60405162461bcd60e51b815260206004820152602260248201527f53657373696f6e4b657956616c696461746f723a2072756e7320657863656564604482015261195960f21b6064820152608490fd5b634e487b7160e01b81526011600452602490fd5b939082610ffd82610ec5565b161561107957600084815260026020526040812033825260205260408120918483549781891692831515600014611060575061103890610ec5565b160190848211610fdd5750908360e0939216955b65ffffffffffff1916868516179055610f05565b91505060e0949392506110739150610ec5565b9561104c565b60405162461bcd60e51b815260206004820152602b60248201527f53657373696f6e4b657956616c696461746f723a20696e76616c69642065786560448201526a637574696f6e2072756c6560a81b6064820152608490fd5b60001981146110e15760010190565b634e487b7160e01b600052601160045260246000fd5b94959391909160009560018060a01b03166000526001968760205260406000203360005260205260406000209365ffffffffffff89860154169560005b6004808401358401013581101561134857600483013583013681900360821901600583901b909101602401351215610518578181101561132a5760fe19863603018160051b870135121561051857611217610a9661120860248460051b600488013588010101356004870135870101606460248201916111e56111b68461064d565b8d6111d2602060018060a01b03928c60051b810135010161064d565b6001600160a01b03909216911614610661565b61120160608d8960051b810135010135604483013511156106b9565b019061061b565b8460051b8a01358a0191611388565b61127e600288015461125f61126d6112368560051b8b01358b0161077f565b604080516020810195865260e09290921b6001600160e01b031916908201529182906044820190565b03601f198101835282610549565b5190208260051b8801358801610ed8565b65ffffffffffff891665ffffffffffff821611611340575b508381101561132a578060051b850135601e19863603018112156105185785018035906001600160401b03821161051857602001908060051b360382136105185761130a91610b438a54918a6040516112ff8161125f60208201948b60051b81013501856107a3565b5190209336916108de565b1561131d57611318906110d2565b611134565b5095989750505050505050565b634e487b7160e01b600052603260045260246000fd5b975038611296565b505050505050509250565b903590601e198136030182121561051857018035906001600160401b0382116105185760200191606082023603831361051857565b600490828211610518576040908185013563ffffffff60e01b80821680920361051857823516036115645760005b608086016113c48188611353565b9050821015611558576113d79087611353565b821015611543576060820201803580860180871161152e57602480830180921161151b57508710610518578301850135602082013560068110156105185780158061150e575b1561143057505050505050505050600090565b6001811480611501575b1561144d57505050505050505050600090565b60028114806114f4575b1561146a57505050505050505050600090565b60038114806114e8575b1561148757505050505050505050600090565b868114806114dc575b156114a357505050505050505050600090565b600586911492836114cf575b5050506114c4576114bf906110d2565b6113b6565b505050505050600090565b01351490503884816114af565b50858301358211611490565b50858301358210611474565b5085830135821015611457565b508583013582111561143a565b508583013582141561141d565b634e487b7160e01b600090815260118952fd5b601187634e487b7160e01b6000525260246000fd5b603285634e487b7160e01b6000525260246000fd5b50505050505050600190565b505050505060009056";

    function deploy() internal returns (address) {
        DeterministicDeploy.checkDeploy("SessionKey", EXPECTED_SESSIONKEY_ADDRESS, SESSIONKEY_CODE);
        return EXPECTED_SESSIONKEY_ADDRESS;
    }
}
