let common = require("./common");
let utils = require("./privacy_utils");
let cs = require("./constants");
let ec = require("./ec.js");

// PrivateKey sk <-- Zn
// PublicKey  pk <-- G*sk
// Plaintext M is a EllipticPoint
// Ciphertext contains 2 EllipticPoint C1, C2
// C1 = G*k
// C2 = pk*k + M
// k <-- Zn is a secret random number

const ElgamalCiphertextSize = 66;

function getPublicKeyFromPrivteKey(privateKeyBytesArrays) {
    let privateKey = new common.BigInt(privateKeyBytesArrays,10,'be');
    return ec.P256.g.mul(privateKey);
}

function Encrypt(publicKeyBytesArray, data) {
    if (!data.isSafe()){
        throw new Error("Data is not safe on P256!");
    }
    let k = utils.RandScalar(32);
    let C1 = ec.P256.g.mul(k);
    let publicKey = ec.P256.decompress(publicKeyBytesArray);
    let C2 = (publicKey.mul(k)).add(data);

    console.log("C1: ", C1);
    console.log("C1: ", C1.compress());
    return C1.compress().concat(C2.compress());
}

function Decrypt(privateKeyBytesArrays, ElgamalCipherText) {
    if (ElgamalCipherText.length!=ElgamalCiphertextSize){
        throw new Error("Cipher in inputs is not Elgamal's ciphertext!");
    }
    let privateKey = new common.BigInt(privateKeyBytesArrays,10,'be');
    let C1 = ec.P256.decompress(ElgamalCipherText.slice(0, cs.CompressPointSize));
    let C2 = ec.P256.decompress(ElgamalCipherText.slice(cs.CompressPointSize, 2*cs.CompressPointSize));
    return C2.add(C1.mul(privateKey).inverse());
}

module.exports = { getPublicKeyFromPrivteKey, Encrypt, Decrypt, ElgamalCiphertextSize}