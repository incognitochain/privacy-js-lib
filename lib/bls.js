const { base64Decode, base64Encode } = require('./privacy_utils');

// seed is bytes array
async function generateBLSKeyPair(seed){
    console.log("bls seed: ", seed);
    let seedStr = base64Encode(seed);

    // console.log("isWASMRunned ", isWASMRunned);
    // console.log("aggregatedRangeProve: ", aggregatedRangeProve);

    console.log("generateBLSKeyPairFromSeed : ", generateBLSKeyPairFromSeed);


    if (typeof generateBLSKeyPairFromSeed  === "function"){
        let keyPairEncoded = await generateBLSKeyPairFromSeed(seedStr);

        let keyPairBytes = base64Decode(keyPairEncoded);

        let privateKey = keyPairBytes.slice(0, 32);
        let publicKey = keyPairBytes.slice(32);

        console.log("bls privateKey: ", privateKey);
        console.log("bls publicKey: ", publicKey);
        console.log("bls publicKey len: ", publicKey.length)

        return {
            blsPrivateKey: privateKey,
            blsPublicKey: publicKey
        }
    } else {
        console.log("Can not call wasm");
    }
}

module.exports = {
    generateBLSKeyPair
}

