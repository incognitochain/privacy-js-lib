const {GenerateECDSAKeyPair} = require('../lib/ecdsa');
const {randBytes, toHexString} = require('../lib/privacy_utils');

function TestECDSA(){
    let seed = [0,1,2,3,4];
    let key = GenerateECDSAKeyPair(seed);
    console.log("Key.ecdsaPrivateKey: ", key.ecdsaPrivateKey);
    console.log("Key.ecdsaPrivateKey hex string: ", toHexString(key.ecdsaPrivateKey));
    console.log("Key.ecdsaPublicKey: ", key.ecdsaPublicKey);

}

TestECDSA();