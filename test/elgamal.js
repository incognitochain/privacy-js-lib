let elgamal = require('../lib/elgamal');
let keyManagement = require('../lib/key');
let utils = require('../lib/privacy_utils');
let P256 = require('../lib/ec').P256;
let assert = require('assert');
describe('Elgamal', function () {
    let PublicKey = null;
    let PrivateKey = null;
    before(function(){
        PrivateKey = keyManagement.GenerateSpendingKey(utils.randBytes());
        PublicKey = elgamal.derivePublicKey(PrivateKey);
    });
    it('Encrypt and decrypt normal value',function () {
        let dataPoint = P256.randomize();
        let res = false;
        let err = null;
        try{
            let cipher = elgamal.encrypt(PublicKey,dataPoint);
            let decryptedPoint = elgamal.decrypt(PrivateKey, cipher);
            res = dataPoint.eq(decryptedPoint);
        } catch (error) {
            err = error;
            res = false;
        } finally {
            assert.ok(res, err);
        }
    });
    it('Encrypt and decrypt wrong value',function () {
        // let dataPoint = P256.randomize();
        // let res = false;
        // let err = null;
        // try{
        //     let cipher = elgamal.encrypt(PublicKey,dataPoint);
        //     let decryptedPoint = elgamal.decrypt(PrivateKey, cipher);
        //     res = dataPoint.eq(decryptedPoint);
        // } catch (error) {
        //     err = error;
        // } finally {
        //     assert.ok(!res, err);
        // }
    });
});