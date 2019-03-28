let estimator = require("./aggregatedrange_utils");

let BigInt = require('bn.js');
let PedCom = require("../pedersen").PedCom;
let ec = require('../ec');
let utils = require('../privacy_utils');
let P256 = ec.P256;
let constants = require('../constants')
function generateChallenge(values) {
    let l = PedCom.GBytes.length;
    let offset = PedCom.GBytes.length;
    for (let i = 0; i < values.length; i++) {
        l += values[i].length;
    }
    let bytes = new Uint8Array(l);
    bytes.set(PedCom.GBytes, 0);

    for (let i = 0; i < values.length; i++) {
        bytes.set(values[i], offset);
        offset += values[i].length;
    }
    let hash = utils.hashSha3BytesToBytes(bytes);
    let res = new BigInt(hash, 10);
    res.umod(P256.n);
    return res
}

function estimateProofSize(nInput, nOutput, hasPrivacy) {
  if (!hasPrivacy) {
        let flagSize = 14+2*nInput+nOutput;
        let sizeSNNoconstantsProof = nInput*constants.SN_NO_PRIVACY_PROOF_SIZE;
        let sizeInputCoins = nInput*constants.INPUT_COINS_NO_PRIVACY_SIZE;
        let sizeOutputCoins = nOutput*constants.OUTPUT_COINS_NO_PRIVACY_SIZE;
        let sizeProof = flagSize + sizeSNNoconstantsProof + sizeInputCoins + sizeOutputCoins;
        return sizeProof
    }
    let flagSize = 14+7*nInput+4*nOutput;
    let sizeOneOfManyProof = nInput * constants.ONE_OF_MANY_PROOF_SIZE;
  let sizeSNPrivacyProof = nInput * constants.SN_PRIVACY_PROOF_SIZE;
  let sizeComOutputMultiRangeProof = estimator.estimateMultiRangeProofSize(nOutput);


    let sizeInputCoins = nInput * constants.INPUT_COINS_PRIVACY_SIZE;
    let sizeOutputCoins = nOutput * constants.OUTPUT_COINS_CONSTANTS_SIZE;

    let sizeComOutputValue = nOutput * constants.COMPRESS_POINT_SIZE;
    let sizeComOutputSND = nOutput * constants.COMPRESS_POINT_SIZE;
    let sizeComOutputShardID = nOutput * constants.COMPRESS_POINT_SIZE;

    let sizeComInputSK = constants.COMPRESS_POINT_SIZE;
    let sizeComInputValue = nInput * constants.COMPRESS_POINT_SIZE;
    let sizeComInputSND = nInput * constants.COMPRESS_POINT_SIZE;
  let sizeComInputShardID = constants.COMPRESS_POINT_SIZE;

  let sizeCommitmentIndices = nInput * constants.CM_RING_SIZE * constants.UINT64_SIZE;

  let sizeProof = sizeOneOfManyProof + sizeSNPrivacyProof +
      sizeComOutputMultiRangeProof + sizeInputCoins + sizeOutputCoins +
      sizeComOutputValue + sizeComOutputSND + sizeComOutputShardID +
      sizeComInputSK + sizeComInputValue + sizeComInputSND + sizeComInputShardID +
      sizeCommitmentIndices + flagSize;
  return sizeProof
}
module.exports = {
  generateChallenge,
  estimateProofSize
}

//     let values =[[38,182,245,255,88,71,47,10,115,26,170,82,236,162,201,123,200,13,250,151,214,25,218,187,168,209,63,19,234,0,54,0],
//     [72,61,92,58,58,29,10,79,54,224,61,8,8,144,178,208,72,114,250,27,117,144,123,150,201,64,26,91,229,71,74,9],
//     [248,79,103,162,8,4,98,59,194,232,126,96,246,93,252,23,252,50,182,42,209,216,89,114,234,194,14,76,75,160,225,111],
//     [133,38,172,236,51,55,146,102,135,105,14,214,206,69,138,133,103,121,34,94,190,29,244,126,118,137,137,255,74,196,226,250]];
// console.log(generateChallenge(values).toString(10));
