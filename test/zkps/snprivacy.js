let snprivacy = require('../../lib/zkps/snprivacy');
let utils = require('../../lib/privacy_utils');
let Pds = require('../../lib/pedersen').PedCom;
let cs = require('../../lib/constants');
let assert = require('assert');
let P256 = require('../../lib/ec').P256;
let BN = require('bn.js')
describe('Serial number privacy', function () {
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
    it('Serial number privacy prove and verify with normal value', function () {
        SND = utils.randScalar();
        let rSND = utils.randScalar();
        let rSK = utils.randScalar();
        serialNumber = (Pds.G[cs.SK].derive(secretKey.toRed(BN.red(P256.n.clone())), SND));
        wit = new snprivacy.SNPrivacyWitness();
        wit.set(serialNumber, Pds.commitAtIndex(secretKey,rSK,cs.SK), Pds.commitAtIndex(SND,rSND,cs.SND), secretKey, rSK, SND, rSND);
        proof = wit.prove();
        assert.ok(proof.verify());
    });
});
