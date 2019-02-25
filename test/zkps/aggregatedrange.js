let aggProtocol = require('../../lib/zkps/aggregatedrange');
let utils = require('../../lib/privacy_utils');
let assert = require('assert');
let bn = require('bn.js');
describe('AggregatedRange Protocol', function(){
    let wit = new aggProtocol.AggregatedRangeWitness();
    let numberOfValue = 2;
    let values  = [];
    let rands  = [];
    beforeEach(function(){
        for (let i = 0; i < numberOfValue; i++) {
            values[i] = new bn("10");
            rands[i] = utils.randScalar(8);
        }
    });
    it('Prove and verify with two normal value', function(){
        wit.set(values,rands);
        let proof = wit.prove();
        assert.ok(proof.verify());
    });
});