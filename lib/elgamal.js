let BigInt = require('bn.js');
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

function derivePublicKey(privateKeyBytesArrays) {
    let privateKey = new BigInt(privateKeyBytesArrays, 10, 'be');
    return ec.P256.g.mul(privateKey);
}

function encrypt(publicKeyBytesArray, data) {
    if (!data.isSafe()) {
        throw new Error("Data is not safe on P256!");
    }
    let k = utils.randScalar(32);
    let C1 = ec.P256.g.mul(k);
    let publicKey = ec.P256.decompress(publicKeyBytesArray);
    let C2 = (publicKey.mul(k)).add(data);
    let res = new Uint8Array(cs.COMPRESS_POINT_SIZE * 2);
    res.set(C1.compress(), 0);
    res.set(C2.compress(), cs.COMPRESS_POINT_SIZE);
    return res;
}

function decrypt(privateKeyBytesArrays, ElgamalCipherText) {
    if (ElgamalCipherText.length != cs.ElgamalCiphertextSize) {
        throw new Error("Cipher in inputs is not Elgamal's ciphertext!");
    }
    let privateKey = new BigInt(privateKeyBytesArrays, 10, 'be');
    let C1 = ec.P256.decompress(ElgamalCipherText.slice(0, cs.COMPRESS_POINT_SIZE));
    let C2 = ec.P256.decompress(ElgamalCipherText.slice(cs.COMPRESS_POINT_SIZE, 2 * cs.COMPRESS_POINT_SIZE));
    return C2.sub(C1.mul(privateKey));
}

module.exports = {
    derivePublicKey,
    encrypt,
    decrypt
}