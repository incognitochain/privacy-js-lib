const {GenerateECDSAPrivateKey} = require('../lib/ecdsa');
const {randBytes} = require('../lib/privacy_utils');

function TestECDSA(){
    for (let i =0; i< 10000; i++){
        let seed = randBytes();
        GenerateECDSAPrivateKey(seed);
    }
}

TestECDSA();