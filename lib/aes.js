let sjcl = require("sjcl");
let utils = require("./privacy_utils");
let cs = require('./constants');

class AES {
    constructor(key){
        // key is a 32-byte array
        this.key = new sjcl.cipher.aes(sjcl.codec.bytes.toBits(key));
    };

    encrypt(data){
        // data is a byte array of arbitrary length
        var iv = new Uint8Array(cs.AESBlockSize + data.length);
        iv.set(utils.randBytes(cs.AESBlockSize),0);
        iv.set(sjcl.codec.bytes.fromBits(sjcl.mode.ctr.encrypt(this.key,sjcl.codec.bytes.toBits(data), sjcl.codec.bytes.toBits(iv.slice(0,cs.AESBlockSize)))),cs.AESBlockSize);
        return iv;
    }

    decrypt(data){ //todo 0xakk0r0kamui

    }
    
}

module.exports = {AES};