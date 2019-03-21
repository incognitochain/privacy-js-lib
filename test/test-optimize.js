

let P256 = require('../lib/ec').P256;
let bn = require('bn.js');


function Test123(){
    let a = BigInt("2783456789034567894567895678905678");
    let aBN = new bn("2783456789034567894567895678905678");

    let sp = BigInt(20);
    let spBN = new bn(20);

    /*console.time("Method 1: ");
    let result1 = P256.g.derive(spBN, aBN);
    console.log("Result1: ", result1);
    console.timeEnd("Method 1: ");

    console.time("Method 2: ");
    let result2 = P256.g.deriveOptimized(sp, a);
    console.log("Result1: ", result2);
    console.timeEnd("Method 2: ");*/


    // console.time("Mul 1: ");
    // let result1 = P256.g.mul(aBN);
    // console.log("Result1: ", result1);
    // console.timeEnd("Mul 1: ");

    // console.time("Mul 2: ");
    // let result2 = P256.g.mulOptimized(a);
    // console.log("Result2: ", result2);
    // console.timeEnd("Mul 2: ");

    console.time("Add addOptimized")
    const temp1 = P256.g.addOptimized(P256.g.hash(0))
    console.timeEnd("Add addOptimized")
    console.log(temp1)

    console.time("Add 2")
    const temp2 = P256.g.add(P256.g.hash(0))
    console.timeEnd("Add 2")
    console.log(temp2)
}

Test123()
