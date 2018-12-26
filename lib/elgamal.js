var common = require("./common");
var crypto = require("crypto");
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
    return ec.Curve.g.mul(privateKey);
}

function Encrypt(publicKeyBytesArray, data) {
    var k = new common.BigInt(crypto.randomBytes(32),10,'be');
    var C1 = ec.Curve.g.mul(k);
    var publicKey = ec.Decompress(publicKeyBytesArray);
    var C2 = (publicKey.mul(k)).add(data);
    var res = new Uint8Array(ElgamalCiphertextSize);
    res.set(ec.Compress(C1),0);
    res.set(ec.Compress(C2),ec.CompressPointSize);
    return res;
}

function Decrypt(privateKeyBytesArrays, ElgamalCipherText) {
    var privateKey = new common.BigInt(privateKeyBytesArrays,10,'be');
    var C1 = ec.Decompress(ElgamalCipherText.slice(0, ec.CompressPointSize));
    var C2 = ec.Decompress(ElgamalCipherText.slice(ec.CompressPointSize, ec.CompressPointSize+ec.CompressPointSize));
    return ec.Sub(C2, C1.mul(privateKey));
}
/* 
    // For testing
var priKeybytearrays = crypto.randomBytes(32);
var plainPoint = ec.Curve.curve.point(new common.BigInt('100222093819885759857726245131128697024676897724593576735535145416600847521071', 10), new common.BigInt('112705950327624587511154978849178363127000253898669394213565898066000545039919', 10));
var publicKeyPoint = getPublicKeyFromPrivteKey(priKeybytearrays);
var publicKeyBytesArrays = ec.Compress(publicKeyPoint);
var CiphertextBytesArrays = Encrypt(publicKeyBytesArrays, plainPoint);
var decryptedPoint = Decrypt(priKeybytearrays,CiphertextBytesArrays);
console.log(ec.IsEqual(plainPoint, decryptedPoint));
    // Test OK
*/

module.exports = { getPublicKeyFromPrivteKey, Encrypt, Decrypt, ElgamalCiphertextSize}