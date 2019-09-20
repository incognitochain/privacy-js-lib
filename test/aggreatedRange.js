const {AggregatedRangeWitness, AggregatedRangeProof} = require('../lib/zkps/aggregatedrange');
const bn = require("bn.js");
const {randBytes, randScalar} = require('../lib/privacy_utils');

async function TestAggregatedRange(){
    let n = 10;
    let values = new Array(n);
    let rands = new Array(n)
    for (let i=0; i<n; i++){
        values[i] = new bn(randBytes(3));
        rands[i] = randScalar();
    }
    let witness = new AggregatedRangeWitness();
    witness.set(values, rands);

    let proof = await witness.prove();

    let proofBytes = proof.toBytes();
    console.log("Proof bytes: ", proofBytes.join(", "));

    let res = proof.verify();
    console.log("Res:", res);

}

TestAggregatedRange()


