const gobridge = require('golang-wasm-async-loader/dist/gobridge');
const {join} = require('path');
require('golang-wasm-async-loader/lib/wasm_exec');
require('isomorphic-fetch');
const {readFileSync} = require('fs');
// var base64js = require('base64-js')
var privacyUtils = require('../lib/privacy_utils');

global.requestAnimationFrame = global.setImmediate;

let p = new Promise(resolve =>
  resolve(readFileSync(join(__dirname, '../privacy.wasm')))
);
const wasm = gobridge.default(p);

async function run() {
  /*let result = await wasm.add(1, 2);
  console.log(result);
  await wasm.sayHello("Bao");*/

  console.time("HHHHHHH time:");
  let object = {
    "values": ["1", "2"],
    "rands": ["100", "200"]
  }
  let proof = await wasm.aggregatedRangeProve(JSON.stringify(object));

  // console.log("proof base64 encode get from WASM: ", proof);
  let proofBytes = privacyUtils.base64Decode(proof);

  console.timeEnd("HHHHHHH time:");
  console.log("proofBytes: ", proofBytes.join(", "));

  let proofEncode = privacyUtils.base64Encode(proofBytes);
  console.log("proofEncode: ", proofEncode);


};

run();