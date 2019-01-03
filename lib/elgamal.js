var common = require("./common");
var utils = require("./privacy_utils");
var cs = require("./constants");
var ec = require("./ec.js");

// PrivateKey sk <-- Zn
// PublicKey  pk <-- G*sk
// Plaintext M is a EllipticPoint
// Ciphertext contains 2 EllipticPoint C1, C2
// C1 = G*k
// C2 = pk*k + M
// k <-- Zn is a secret random number

const ElgamalCiphertextSize = 66;

function getPublicKeyFromPrivteKey(privateKeyBytesArrays) {
    var privateKey = new common.BigInt(privateKeyBytesArrays,10,'be');
    return ec.P256.g.mul(privateKey);
}

function Encrypt(publicKeyBytesArray, data) {
    var k = utils.RandInt(32);
    var C1 = ec.P256.g.mul(k);
    var publicKey = ec.P256.decompress(publicKeyBytesArray);
    var C2 = (publicKey.mul(k)).add(data);
    var res = new Uint8Array(ElgamalCiphertextSize);
    res.set(C1.compress(),0);
    res.set(C2.compress(),cs.CompressPointSize);
    return res;
}

function Decrypt(privateKeyBytesArrays, ElgamalCipherText) {
    var privateKey = new common.BigInt(privateKeyBytesArrays,10,'be');
    var C1 = ec.P256.decompress(ElgamalCipherText.slice(0, cs.CompressPointSize));
    var C2 = ec.P256.decompress(ElgamalCipherText.slice(cs.CompressPointSize, cs.CompressPointSize+cs.CompressPointSize));
    return C2.add(C1.mul(privateKey).inverse());
}

    // For testing
var priKeybytearrays = utils.RandBytes(32);
// var plainPoint = ec.P256.curve.point(new common.BigInt('100222093819885759857726245131128697024676897724593576735535145416600847521071', 10), new common.BigInt('112705950327624587511154978849178363127000253898669394213565898066000545039919', 10));
var plainPoint = ec.P256.randomize();
var publicKeyPoint = getPublicKeyFromPrivteKey(priKeybytearrays);
var publicKeyBytesArrays = publicKeyPoint.compress();
var CiphertextBytesArrays = Encrypt(publicKeyBytesArrays, plainPoint);
var decryptedPoint = Decrypt(priKeybytearrays,CiphertextBytesArrays);
console.log(plainPoint.eq(decryptedPoint));
    // Test OK




module.exports = { getPublicKeyFromPrivteKey, Encrypt, Decrypt, ElgamalCiphertextSize}