let snnoprivacy = require('../../lib/zkps/snnoprivacy');
let utils = require('../../lib/privacy_utils');
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
        secretKey = utils.randScalar();
        publicKey = P256.g.mul(secretKey).compress();
    });
    it('Serial number no privacy prove and verify with normal value', function () {
        SND = utils.randScalar();
        serialNumber = (Pds.G[cs.SK].derive(secretKey, SND));
        wit = new snnoprivacy.SNNoPrivacyWitness();
        wit.set(serialNumber, P256.decompress(publicKey), SND, secretKey);
        proof = wit.prove();
        assert.ok(proof.verify());
    });
});