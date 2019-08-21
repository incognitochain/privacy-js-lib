const Elliptic = require('elliptic').ec;
const secp256k1 = new Elliptic('secp256k1');
const { hashKeccakBytesToBytes } = require("./privacy_utils");
const { COMPRESS_POINT_SIZE, BIG_INT_SIZE } = require('./constants');

// generateECDSAKeyPair generates ECDSA key pair from seed
function generateECDSAKeyPair(seed) {
    let hash = hashKeccakBytesToBytes(seed);
    let keyPair = secp256k1.keyFromPrivate(hash);
    let privateKey = keyPair.getPrivate();
    let publicKey = keyPair.getPublic();

    return {
        ecdsaPrivateKey: privateKey.toArray(),
        ecdsaPublicKey: publicKey.encodeCompressed()
    }
}

// // GenerateBLSKeyPair generates BLS key pair from seed
// function GenerateBLSKeyPair(seed) {
//     let hash = hashKeccakBytesToBytes(seed);
//     let keyPair = secp256k1.keyFromPrivate(hash);
//     let privateKey = keyPair.getPrivate();
//     let publicKey = keyPair.getPublic();

//     return {
//         ecdsaPrivateKey: privateKey.toArray(),
//         ecdsaPublicKey: publicKey.encodeCompressed()
//     }
// }

module.exports = {
    generateECDSAKeyPair,
}