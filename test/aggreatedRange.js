const {AggregatedRangeWitness, AggregatedRangeProof} = require('../lib/zkps/aggregatedrange');
const bn = require("bn.js");

async function TestAggregatedRange(){
    // let values = [new bn('1000000'), new bn('2000000')];
    let values = [new bn('1000000000000000'), new bn('2000000000000000')];
    let rand = [new bn(10), new bn(20)];
    let witness = new AggregatedRangeWitness();
    witness.set(values, rand);

    let proof = await witness.prove();

    let proofBytes = proof.toBytes();
    console.log("Proof bytes: ", proofBytes.join(", "));

    let res = proof.verify();
    console.log("Res:", res);

}

TestAggregatedRange()


