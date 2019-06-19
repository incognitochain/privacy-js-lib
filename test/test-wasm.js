const gobridge = require('golang-wasm-async-loader/dist/gobridge');
const { join } = require('path');
require('golang-wasm-async-loader/lib/wasm_exec');
require('isomorphic-fetch');
const { readFileSync } = require('fs');

global.requestAnimationFrame = global.setImmediate;

let p = new Promise(resolve =>
  resolve(readFileSync(join(__dirname, '../privacy.wasm')))
);
const wasm = gobridge.default(p);

async function run() {
  let result = await wasm.add(1, 2);
  console.log(result);
  await wasm.sayHello("asfasf");

  let proof = await wasm.aggregatedRangeProve({"values":["1","2"],"rands":["64","c8"]});
  console.log("proof: ", proof);
};

run();