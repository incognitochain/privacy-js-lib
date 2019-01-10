let common = require('../common');
let ec = require('../ec');
let P256 = require('../ec').P256;
let constants = require('../constants');
let key = require('../key');
let utils = require('../privacy_utils');
let aes = require('../aes');
let elgamal = require('../elgamal');


class OneOutOfManyWitness {
    constructor() {
        this.rand = new common.BigInt(0);
        this.indexIsZero = 0;
        this.commitments = [];
        this.commitmentIndices = [];
        this.index = 0;
    }

    set(commitments, commitmentIndexs, rand, indexIsZero, index) {
        this.commitments = commitments;
        this.commitmentIndices = commitmentIndexs;
        this.rand = rand;
        this.indexIsZero = indexIsZero;
        this.index = index;
    }
    prove(){
        return new OneOutOfManyProof();
    }

}

class OneOutOfManyProof {
    constructor() {
        this.cl = [];          // []EllipticPoint
        this.ca = [];          // []EllipticPoint
        this.cb = [];          // []EllipticPoint
        this.cd = [];          // []EllipticPoint
        this.f = [];           // [] BigInt
        this.za = [];          // [] BigInt
        this.zb = [];          // [] BigInt
        this.zd = new common.BigInt(0);
        this.commitments = [];
        this.commitmentIndices = [];
        this.index = 0;
    }

    isNull() {
        if (this.cl.length === 0) {
            return true;
        }
        if (this.ca.length === 0) {
            return true;
        }
        if (this.cb.length === 0) {
            return true;
        }
        if (this.cd.length === 0) {
            return true;
        }
        if (this.f.length === 0) {
            return true;
        }
        if (this.za.length === 0) {
            return true;
        }
        if (this.zb.length === 0) {
            return true;
        }
        if (this.zd.eq(0)) {
            return true;
        }
        if (this.commitments.length === 0) {
            return true;
        }
        if (this.commitmentIndices.length === 0) {
            return true;
        }
        return this.index === 0;
    }

    set(commitmentIndices, commitments, cl, ca, cb, cd, f, za, zb, zd, index) {
        this.commitmentIndices = commitmentIndices;
        this.commitments = commitments;
        this.cl = cl;
        this.ca = ca;
        this.cb = cb;
        this.cd = cd;
        this.f = f;
        this.za = za;
        this.zb = zb;
        this.zd = zd;
        this.index = index;
        return this;
    }
    toBytes(){
        // if proof is null, return an empty array
        if (this.isNull()) {
            return [];
        }

        // N = 2^n
        let N = constants.CMRingSize;
        let n = constants.CMRingSizeExp;

        let bytes = [];

        // convert array cl to bytes array
        for (let i = 0; i < n; i++) {
            bytes = bytes.concat(this.cl[i].compress());
        }
        // convert array ca to bytes array
        for (let i = 0; i < n; i++) {
            bytes = bytes.concat(this.ca[i].compress());
        }

        // convert array cb to bytes array
        for (let i = 0; i < n; i++) {
            bytes = bytes.concat(bytes, this.cb[i].compress());
        }

        // convert array cd to bytes array
        for (let i = 0; i < n; i++) {
            bytes = bytes.concat(this.cd[i].compress());
        }
        return bytes;
    }
}

module.exports = {OneOutOfManyWitness, OneOutOfManyProof }
