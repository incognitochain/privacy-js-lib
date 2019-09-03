const {generateECDSAKeyPair} = require('../lib/ecdsa');
const {randBytes, toHexString} = require('../lib/privacy_utils');

function TestECDSA(){
    let seed = [0,1,2,3,4];
    let key = generateECDSAKeyPair(seed);
    console.log("Key.ecdsaPrivateKey: ", key.ecdsaPrivateKey);
    console.log("Key.ecdsaPrivateKey hex string: ", toHexString(key.ecdsaPrivateKey));
    console.log("Key.ecdsaPublicKey: ", key.ecdsaPublicKey);
    console.log("Key.ecdsaPublicKey.length: ", key.ecdsaPublicKey.length);

}

TestECDSA();