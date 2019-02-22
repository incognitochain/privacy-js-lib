let snnoprivacy = require('../../lib/zkps/snnoprivacy');
let utils = require('../../lib/privacy_utils');
let keys = require('../../lib/key');
let Pds = require('../../lib/pedersen').PedCom;
let cs = require('../../lib/constants');
let assert = require('assert');
let BigInt = require('bn.js');
let P256 = require('../../lib/ec').P256;
describe('Serial number no privacy', function () {
    let secretKey = null;
    let publicKey = null;
    let serialNumber = null;
    let SND = null;
    let wit = null;
    let proof = null;
    before(function () {
        secretKey = keys.GenerateSpendingKey(utils.randBytes());
        publicKey = keys.GeneratePublicKey(secretKey);
        console.log("aaaa");
    });
    it('Serial number no privacy prove and verify with normal value', function () {
        console.log("bbbb");
        SND = utils.randScalar();
        serialNumber = (Pds.G[cs.SK].derive(new BigInt(secretKey,10), SND));
        wit = new snnoprivacy.SNNoPrivacyWitness();
        wit.set(serialNumber, P256.decompress(publicKey), SND, new BigInt(secretKey,10));
        proof = wit.prove();
        console.log(publicKey,wit, proof);
        assert.ok(proof.verify());
    });
});