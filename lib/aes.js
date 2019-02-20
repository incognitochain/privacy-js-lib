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
        var iv = new Uint8Array(cs.AES_BLOCK_SIZE + data.length);
        iv.set(utils.randBytes(cs.AES_BLOCK_SIZE),0);
        iv.set(sjcl.codec.bytes.fromBits(sjcl.mode.ctr.encrypt(this.key,sjcl.codec.bytes.toBits(data), sjcl.codec.bytes.toBits(iv.slice(0,cs.AES_BLOCK_SIZE)))),cs.AES_BLOCK_SIZE);
        return iv;
    }

    decrypt(data){
        var iv = data.slice(0,cs.AES_BLOCK_SIZE);
        var ct = data.slice(cs.AES_BLOCK_SIZE, data.length);
        return sjcl.codec.bytes.fromBits(sjcl.mode.ctr.decrypt(this.key,sjcl.codec.bytes.toBits(ct),sjcl.codec.bytes.toBits(iv)));
    }
    
}

// let aes = new AES(utils.randBytes());
// console.log(aes.decrypt(aes.encrypt([0,2,3,4,5,6])));
module.exports = {AES};