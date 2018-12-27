const ECC = require('elliptic');
const Elliptic = ECC.ec;
const BigInt = require('bn.js');

const sjcl = require('sjcl');
function HashBytesToBytes(data){
    return sjcl.codec.bytes.fromBits(sjcl.hash.sha256.hash(stringFromUTF16Array(data)));
}
function DoubleHashBytesToBytes(data){
    return sjcl.codec.bytes.fromBits(sjcl.hash.sha256.hash(sjcl.hash.sha256.hash(stringFromUTF16Array(data))))
}

console.log(HashBytesToBytes([93, 92,91,90]));
console.log(DoubleHashBytesToBytes([93, 92,91,90]));

module.exports = { HashBytesToBytes, DoubleHashBytesToBytes, ECC, Elliptic , BigInt};

function stringFromUTF16Array(data) {
    return decodeURIComponent(function(data){
        var i, str = '';
        for (i=0; i<data.length; i++){
            str += '%' + (data[i].toString(16)).slice(-2);
        }
        return str
    }(data));
}

