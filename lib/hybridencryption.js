let common = require('./common');
let ec = require('./ec.js');
let P256 = ec.P256;
let aes = require('./aes');
let elgamal = require('./elgamal');

class Ciphertext{
    constructor(){
        this.msgEncrypted = [];
        this.symKeyEncrypted = [];
    }

    isNull(){
        if (this.msgEncrypted.length === 0){
            return true;
        }
        return this.symKeyEncrypted.length === 0
    }

    // toBytes converts ciphertext to bytes array
    toBytes(){
        let bytes = new Uint8Array(this.msgEncrypted.length + this.symKeyEncrypted.length);
        bytes.set(this.symKeyEncrypted, 0);
        bytes.set(this.msgEncrypted, this.symKeyEncrypted.length);
        return bytes;
    }
}

function hybridencryption(msg, publicKey){
    let ciphertext = new Ciphertext();

    // Generate a AES key as the abscissa of a random elliptic point
    let aesKeyPoint = P256.randomize();
    let aesKeyByte = aesKeyPoint.getX().toArray();

    // Encrypt msg using aesKeyByte
    let aesScheme = new aes.AES(aesKeyByte);
    ciphertext.msgEncrypted = aesScheme.Encrypt(msg);

    // Using ElGamal cryptosystem for encrypting AES sym key
    ciphertext.symKeyEncrypted = elgamal.Encrypt(publicKey, aesKeyPoint);

    return ciphertext
}

function TestHybridEncrypt(){
    let msg = [10, 20];
    let privateKey = new common.BigInt(10);
    console.log('Private key : ', privateKey.toArray().join(', '));
    let publicKey = P256.g.mul(privateKey);
    console.log("public key : ", publicKey.compress().join(', '));

    let ciphertext = hybridencryption(msg, publicKey.compress());
    console.log("Ciphertext msg when encrypt: ", ciphertext.msgEncrypted.join(', '));

    console.log('ciphertext: ', ciphertext.toBytes().join(', '));
}

// TestHybridEncrypt();

module.exports ={Ciphertext, hybridEncrypt: hybridencryption};