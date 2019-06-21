let agg = require('../lib/zkps/aggregatedrange');
let bn = require('bn.js');

let js = require('browserify-fs');

function TestReadFile(){
    let res = js.readFile('./text.txt');
    console.log("res: ", res);
}

TestReadFile()

function Test(){
    let wit = new(agg.AggregatedRangeWitness);
    let values = [new bn(1), new bn(2)];
    let rands = [new bn(100), new bn(200)];

    wit.set(values, rands);
    console.log()
    witStr = JSON.stringify(wit);
    console.log("witStr: ", witStr);

}

// Test()