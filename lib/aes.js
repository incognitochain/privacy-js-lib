const sjcl = require("sjcl");
const utils = require("./privacy_utils");
const Blocksize = 16
class AES {
    constructor(keys){
        this.key = new sjcl.cipher.aes(sjcl.codec.bytes.toBits(keys));
    };

    Encrypt(data){
        var iv = new Uint8Array(Blocksize + data.length);
        iv.set(utils.RandBytes(Blocksize),0);
        iv.set(sjcl.codec.bytes.fromBits(sjcl.mode.ctr.encrypt(this.key,sjcl.codec.bytes.toBits(data), sjcl.codec.bytes.toBits(iv.slice(0,Blocksize)))),Blocksize);
        return iv;
    }
    Decrypt(data){
        return null;
    }
}
// var a = new AES([52,192,174,89,231,188,123,129,205,105,139,229,66,90,16,202,155,246,232,223,181,3,224,199,201,76,210,240,61,32,127,54])
// console.log(a.Encrypt([0,92,1,200,255]));

module.exports = {AES};