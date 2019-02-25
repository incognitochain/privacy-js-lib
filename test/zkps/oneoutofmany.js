let outOfManyProtocol = require('../../lib/zkps/oneoutofmany');
let constants = require('../../lib/constants');
let bn = require('bn.js');
let assert = require('assert');
let P256 = require('../../lib/ec').P256;
let Pds = require('../../lib/pedersen').PedCom;
describe('One out of many', function () {
    let N = constants.CM_RING_SIZE;
    let n = constants.CM_RING_SIZE_EXP;
    let commitments = new Array(N);
    let indexIsZero = 3;
    let randIsZero = null;
    let wit = new outOfManyProtocol.OneOutOfManyWitness();
    let proof = null;
    before(function () {
        commitments[0] = P256.decompress([2, 63, 242, 198, 114, 250, 36, 102, 85, 80, 173, 148, 153, 247, 78, 215, 30, 54, 40, 193, 40, 190, 206, 73, 198, 39, 23, 48, 56, 136, 58, 91, 167]);
        commitments[1] = P256.decompress([2, 203, 30, 129, 126, 123, 135, 125, 29, 43, 137, 52, 148, 146, 17, 87, 85, 237, 67, 191, 175, 241, 86, 102, 239, 183, 114, 78, 11, 127, 116, 16, 143]);
        commitments[2] = P256.decompress([2, 123, 251, 169, 31, 79, 237, 122, 212, 173, 208, 175, 20, 111, 140, 19, 185, 72, 17, 229, 163, 84, 255, 63, 157, 51, 251, 209, 160, 122, 250, 30, 116]);
        commitments[3] = P256.decompress([2, 174, 247, 205, 128, 120, 191, 95, 219, 186, 227, 95, 10, 157, 200, 224, 109, 152, 179, 5, 188, 162, 125, 167, 214, 127, 178, 173, 246, 109, 18, 23, 254]);
        commitments[4] = P256.decompress([2, 8, 49, 76, 243, 238, 108, 171, 35, 55, 118, 239, 95, 214, 43, 88, 155, 4, 152, 62, 74, 15, 62, 203, 158, 189, 163, 62, 150, 255, 220, 14, 170]);
        commitments[5] = P256.decompress([3, 205, 17, 244, 179, 44, 154, 114, 20, 78, 113, 196, 20, 133, 98, 165, 111, 74, 139, 53, 74, 224, 153, 41, 66, 224, 190, 220, 179, 136, 193, 241, 218]);
        commitments[6] = P256.decompress([3, 191, 145, 66, 202, 76, 92, 64, 185, 89, 85, 149, 239, 190, 231, 208, 214, 25, 0, 218, 142, 114, 18, 188, 122, 111, 213, 6, 108, 128, 129, 122, 109]);
        commitments[7] = P256.decompress([2, 186, 15, 36, 170, 79, 9, 118, 9, 249, 10, 215, 114, 5, 80, 9, 156, 206, 217, 242, 156, 30, 210, 169, 109, 221, 103, 37, 186, 24, 88, 47, 121]);
    });
    it('Prove and verify one out of many protocol with normal value', function () {
        randIsZero = new bn(100);
        commitments[indexIsZero] = Pds.commitAtIndex(0, randIsZero, constants.SK);
        wit.set(commitments, randIsZero, indexIsZero);
        proof = wit.prove();
        assert.ok(proof.err == null, 'Prove function of One out of many protocol has error');
        if (proof.err != null) {
            assert.ok(proof.proof.verify());
        }
    });
});