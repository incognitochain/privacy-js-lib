const sjcl = require("sjcl");
// var aes = sjcl.cipher.aes([0x00000000,0x00000000,0x00000000,0x00000001]);
// var iv = [0x00000000,0x00000000,0x00000000,0x00000001];
const Blocksize = 16
class AES {
    constructor(keys){
        this.key = new sjcl.cipher.aes(sjcl.codec.bytes.toBits(keys));
    };

    Encrypt(data){
        var iv = [63,215,145,72,91,205,87,235,46,35,13,115,4,34,62,10]
        return sjcl.mode.ctr.encrypt(this.key,sjcl.codec.bytes.toBits(data), sjcl.codec.bytes.toBits(iv));
    }
    Decrypt(data){
        return null;
    }
}
var a = new AES([52,192,174,89,231,188,123,129,205,105,139,229,66,90,16,202,155,246,232,223,181,3,224,199,201,76,210,240,61,32,127,54])
console.log(sjcl.codec.bytes.fromBits(a.Encrypt([0])))

module.exports = {AES};