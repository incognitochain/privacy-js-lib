let BigInt = require('bn.js');
let ec = require('./ec.js');
let P256 = ec.P256;
let aes = require('./aes');
let elgamal = require('./elgamal');

class Ciphertext {
    // constructor initializes a new empty ciphertext
    constructor() {
        this.msgEncrypted = [];
        this.symKeyEncrypted = [];
    }

    // isNull returns true if msgEncrypted or symKeyEncrypted are empty, false otherwise
    isNull() {
        if (this.msgEncrypted.length === 0 || this.symKeyEncrypted.length === 0) {
            return true;
        }
        return false;
    }

    // toBytes converts a ciphertext to a byte array
    toBytes() {
        let bytes = new Uint8Array(this.msgEncrypted.length + this.symKeyEncrypted.length);
        bytes.set(this.symKeyEncrypted, 0);
        bytes.set(this.msgEncrypted, this.symKeyEncrypted.length);
        return bytes;
    }
}

// hybridEncrypt encrypts msg with publicKey using ElGamal cryptosystem
function hybridEncrypt(msg, publicKey) {
    // Initialize a ciphertext
    let ciphertext = new Ciphertext();

    // Generate a AES key as the abscissa of a random elliptic point
    let aesKeyPoint = P256.randomize();
    let aesKeyByte = aesKeyPoint.getX().toArray();

    // Encrypt msg using aesKeyByte
    let aesScheme = new aes.AES(aesKeyByte);
    ciphertext.msgEncrypted = aesScheme.Encrypt(msg);

    // Encrypt aesKeyByte using ElGamal cryptosystem
    ciphertext.symKeyEncrypted = elgamal.Encrypt(publicKey, aesKeyPoint);

    return ciphertext
}

// test function for hybridEncrypt
function testHybridEncrypt() {
    let msg = [10, 20];
    let privateKey = new BigInt(10);
    console.log('Private key : ', privateKey.toArray().join(', '));
    let publicKey = P256.g.mul(privateKey);
    console.log("public key : ", publicKey.compress().join(', '));

    let ciphertext = hybridEncrypt(msg, publicKey.compress());
    console.log("Ciphertext msg when encrypt: ", ciphertext.msgEncrypted.join(', '));

    console.log('ciphertext: ', ciphertext.toBytes().join(', '));
}

// testHybridEncrypt();

module.exports = {
    Ciphertext,
    hybridEncrypt: hybridEncrypt
};