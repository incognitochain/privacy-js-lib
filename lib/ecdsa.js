const Elliptic = require('elliptic').ec;
const secp256k1 = new Elliptic('secp256k1');
const { hashSha3BytesToBytes } = require("./privacy_utils");
const { COMPRESS_POINT_SIZE, BIG_INT_SIZE } = require('./constants');

// GenerateECDSAKeyPair generates ECDSA key pair from seed
function GenerateECDSAKeyPair(seed) {
    let hash = hashSha3BytesToBytes(seed);
    let keyPair = secp256k1.keyFromPrivate(hash);
    let privateKey = keyPair.getPrivate();
    let publicKey = keyPair.getPublic();

    return {
        ecdsaPrivateKey: privateKey.toArray(),
        ecdsaPublicKey: publicKey.encodeCompressed()
    }
}

module.exports = {
    GenerateECDSAKeyPair,
}