var privacyUtils = require('../lib/privacy_utils');

require('isomorphic-fetch');
require("../wasm_exec")
var fs = require('fs');
const go = new Go();
let inst;
if (fs.readFileSync) {
  let data = fs.readFileSync("../privacy1.wasm")
  WebAssembly.instantiate(data, go.importObject).then(async (result) => {
    inst = result.instance;
    go.run(inst);
    await sleep(3000)
  });
} else {
  if (!WebAssembly.instantiateStreaming) { // polyfill
    WebAssembly.instantiateStreaming = async (resp, importObject) => {
      const source = await (await resp).arrayBuffer();
      return await WebAssembly.instantiate(source, importObject);
    };
  }
  WebAssembly.instantiateStreaming(fetch("../privacy1.wasm"), go.importObject).then(async (result) => {
    inst = result.instance;
    go.run(inst);
    await sleep(3000)
  });
}

async function sleep(sleepTime) {
  return new Promise(resolve => setTimeout(resolve, sleepTime));
}

async function run() {
  console.time("HHHHHHH time:");
  let object = {
    "values": ["1", "2"],
    "rands": ["100", "200"]
  }
  await sleep(3000)
  // console.log(global.global.add)
  // let result = global.global.add(1, 2)
  // console.log(result)
  let proof = await aggregatedRangeProve(JSON.stringify(object));

  // console.log("proof base64 encode get from WASM: ", proof);
  let proofBytes = privacyUtils.base64Decode(proof);

  console.timeEnd("HHHHHHH time:");
  console.log("proofBytes: ", proofBytes.join(", "));

  let proofEncode = privacyUtils.base64Encode(proofBytes);
  console.log("proofEncode: ", proofEncode);
}
;

run();