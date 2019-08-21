const { base64Decode, base64Encode } = require('./privacy_utils');


let isWASMRunned = false;
try{
  if (!isWASMRunned){
    require('isomorphic-fetch');
    require("../wasm_exec")
    var fs = require('fs');
    const go = new Go();
    let inst;
    if (fs.readFileSync) {
      let data;
      try{
        data = fs.readFileSync("./privacy.wasm")
        console.log("REadinggggggggggg ");
        console.log("data: ", data);
      } catch(e){
        console.log(e);
      }
      
      WebAssembly.instantiate(data, go.importObject).then((result) => {
        inst = result.instance;
        go.run(inst);
        isWASMRunned = true;
      });

    
    } else {
      if (!WebAssembly.instantiateStreaming) { // polyfill
        WebAssembly.instantiateStreaming = async (resp, importObject) => {
          const source = await (await resp).arrayBuffer();
          console.log("WebAssembly source", source);
          return await WebAssembly.instantiate(source, importObject);
        };
      }
      WebAssembly.instantiateStreaming(fetch("./privacy.wasm"), go.importObject).then(async (result) => {
        inst = result.instance;
        go.run(inst);
        isWASMRunned = true;
      });
    }
  }
} catch(e){
  console.log("Running on mobile app: ", e);
}
// seed is bytes array
function generateBLSKeyPair(seed){
    console.log("bls seed: ", seed);
    let seedStr = base64Encode(seed);

    console.log("isWASMRunned ", isWASMRunned);
    console.log("aggregatedRangeProve: ", aggregatedRangeProve);

    console.log("generateBLSKeyPairFromSeed : ", generateBLSKeyPairFromSeed);
  
    
    if (typeof generateBLSKeyPairFromSeed  === "function"){
        let keyPairEncoded = generateBLSKeyPairFromSeed(seedStr);

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

