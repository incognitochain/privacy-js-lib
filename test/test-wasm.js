const gobridge = require('golang-wasm-async-loader/dist/gobridge');
const {join} = require('path');
require('golang-wasm-async-loader/lib/wasm_exec');
require('isomorphic-fetch');
const {readFileSync} = require('fs');
var base64js = require('base64-js')

global.requestAnimationFrame = global.setImmediate;

let p = new Promise(resolve =>
  resolve(readFileSync(join(__dirname, '../privacy.wasm')))
);
const wasm = gobridge.default(p);

function base64Decode(str){
  let bytes = base64js.toByteArray(str);
  console.log("bytes: ", bytes);
  return bytes;
}

function base64Encode(bytesArray){
  let str = base64js.fromByteArray(bytesArray);
  console.log("str: ", str);
  return str;
}

async function run() {
  let result = await wasm.add(1, 2);
  console.log(result);
  await wasm.sayHello("Bao");

  console.time("HHHHHHH time:");
  let object = {
    "values": ["1", "2"],
    "rands": ["100", "200"]
  }
  let proof = await wasm.aggregatedRangeProve(JSON.stringify(object));

  // console.log("proof base64 encode get from WASM: ", proof);
  let proofBytes = base64Decode(proof);

  console.timeEnd("HHHHHHH time:");
  console.log("proofBytes: ", proofBytes.join(", "));

  let proofEncode = base64Encode(proofBytes);
  console.log("proofEncode: ", proofEncode);


}; 

run();