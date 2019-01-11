let common = require("../common");
let ec = require("../ec");
let Pds = require("../pedersen").PedCom;
let cs = require("../constants");
let utils = require("../privacy_utils");

/*------------ This just is interface ------------*/

class SNPrivacyProof {
    constructor(){

    }

    toBytes(){
        return [];
    }
}


class SNPrivacyWitness {
    constructor(){

    }

    prove(){

        return new SNPrivacyProof();
    }
}

module.exports = {SNPrivacyWitness, SNPrivacyProof};

