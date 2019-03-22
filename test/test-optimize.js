

let P256 = require('../lib/ec').P256;
let bn = require('bn.js');
let ec = require('../lib/ec');


function Test123(){
    let a = BigInt("2783456789034567894567895678905678");
    let aBN = new bn("2783456789034567894567895678905678");
    let twoBN = BigInt(3);

    let sp = BigInt(20);
    let spBN = new bn(20);

    // console.time("derive: ");
    // let result1 = P256.g.derive(spBN, aBN);
    // console.log("Result1: ", result1);
    // console.timeEnd("derive: ");

    // console.time("deriveOptimized: ");
    // let result2 = P256.g.deriveOptimized(sp, a);
    // console.log("Result1: ", result2);
    // console.timeEnd("deriveOptimized: ");
    // -----------------------------------

    console.time("Mul 1: ");
    let result1 = P256.g.mul(new bn(3));
    console.log("Result1: ", result1);
    console.timeEnd("Mul 1: ");

    console.time("Mul optimized: ");
    let result2 = P256.g.mulOptimized(twoBN);
    console.log("Result2: ", result2);
    console.timeEnd("Mul optimized: ");

    console.time("Mul optimized 2: ");
    let result3 = P256.g.mulOptimized2(twoBN);
    console.log("Result3: ", result3);
    console.timeEnd("Mul optimized 2: ");

    // -----------------------------------
    // add point 
    // let g2 = P256.g.hash(1);

    // let g2 = P256.g;
    // let g22 = {x: BigInt(g2.x.fromRed().toString()), y: BigInt(g2.y.fromRed().toString())}


    // console.time("Add addOptimized")
    // const temp1 = P256.g.addOptimized(g2)
    // console.timeEnd("Add addOptimized")
    // console.log(temp1)

    // let g = {x: BigInt(P256.g.x.fromRed().toString()), y: BigInt(P256.g.y.fromRed().toString())}
    // console.time("Add addOptimized 2")
    // const temp3 = ec.addOptimized2(g, g22);
    // console.timeEnd("Add addOptimized 2")
    
    // let ctx = bn.red( P256.curve.p)
    // let res = P256.curve.point(new bn(temp3.x.toString()).toRed(ctx), new bn(temp3.y.toString(10)).toRed(ctx));
   
    // console.log(res);

    // console.time("Add normal")
    // const temp2 = P256.g.add(g2)
    // console.timeEnd("Add normal")
    // console.log(temp2)

    // -----------------------------------
    // test big int
    // const P = bn.red(P256.p.clone());
    // let numRed1 = P256.n.clone().toRed(P);
    // console.log("P256.n: ", P256.n);
    // console.log("numRed1: ", numRed1);
    // let numBigInt = BigInt(P256.n.toString());

    // console.time("Add red")
    // const res1 = numRed1.add(numRed1)
    // console.timeEnd("Add red")
    // console.log(res1)

    // console.time("Add BigInt")
    // const res2 = numBigInt + numBigInt;
    // console.timeEnd("Add BigInt")
    // console.log(new bn(res2.toString()))


}

Test123()
