const {OneOutOfManyWitness, OneOutOfManyProof} = require("../lib/zkps/oneoutofmany");
const {randScalar} = require("../lib/privacy_utils");
const {CM_RING_SIZE} = require("../lib/zkps/constants");
const {PedCom} = require("../lib/pedersen");
const {SND} = require("../lib/constants");
const bn = require("bn.js");

async function sleep(sleepTime) {
    return new Promise(resolve => setTimeout(resolve, sleepTime));
}

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
            data = fs.readFileSync("../privacy.wasm")
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

//TestPKOneOfMany test protocol for one of many Commitment is Commitment to zero
async function TestPKOneOfMany() {

    await sleep(5000);
	// prepare witness for Out out of many protocol

	for (let i = 0; i < 1000; i++) {
		let witness = new(OneOutOfManyWitness)

		let indexIsZero = randScalar(1).toNumber() % CM_RING_SIZE;

		// list of commitments
		let commitments = [];
		let snDerivators = [];
		let randoms = [];

		for (let i = 0; i < CM_RING_SIZE; i++){
			snDerivators[i] = randScalar()
			randoms[i] = randScalar()
			commitments[i] = PedCom.commitAtIndex(snDerivators[i], randoms[i], SND)
		}

		// create Commitment to zero at indexIsZero
		snDerivators[indexIsZero] = new bn(0);
		commitments[indexIsZero] = PedCom.commitAtIndex(snDerivators[indexIsZero], randoms[indexIsZero], SND)

		witness.set(commitments, randoms[indexIsZero], indexIsZero)
		// start := time.Now()
        let result = await witness.prove()
        // console.log("Result proving: ", result);
		// assert.Equal(t, nil, err)
		// end := time.Since(start)
		//fmt.Printf("One out of many proving time: %v\n", end)

		// // validate sanity for proof
		// isValidSanity := proof.ValidateSanity()
		// assert.Equal(t, true, isValidSanity)

		//Convert proof to bytes array
		let proofBytes = result.proof.toBytes()
		// assert.Equal(t, utils.OneOfManyProofSize, len(proofBytes))

		// revert bytes array to proof
		let proof2 = new OneOutOfManyProof();
		proof2.setBytes(proofBytes);
		proof2.stmt.commitments = commitments
		// assert.Equal(t, proof, proof2)
		// proof2.Statement.Commitments[3] = new(privacy.EllipticPoint)
		// proof2.Statement.Commitments[3].Randomize()

		// verify the proof
		// start = time.Now()
        let res = proof2.verify();
        console.log("Res: ", res);

        if (!res) {
            console.log();
            console.log();
            console.log();
            console.log("Wrong!!!!");
            break;
        }
		// end = time.Since(start)
		// fmt.Printf("One out of many verification time: %v\n", end)
		// assert.Equal(t, true, res)
		// assert.Equal(t, nil, err)
	}
}

TestPKOneOfMany()