let common = require('../common');
let ec = require('../ec');
const P256 = require('../ec').P256;
let constants = require('../constants');
const utils = require('../privacy_utils');
const zkpUtils = require('./utils');
const pc = require('../pedersen');
let poly = require('../polynomials');


class OneOutOfManyStatement {
    constructor() {
        this.commitments = [];
    }

    set(commitments) {
        this.commitments = commitments
    }
}


class OneOutOfManyWitness {
    constructor() {
        this.rand = new common.BigInt(0);
        this.indexIsZero = 0;
        this.stmt = new OneOutOfManyStatement();
    }

    set(commitments, rand, indexIsZero) {
        this.rand = rand;
        this.indexIsZero = indexIsZero;
        this.stmt.set(commitments);
    }

    prove() {
        // Check the number of Commitment list's elements
        let N = this.stmt.commitments.length;
        if (N !== constants.CMRingSize) {
            return {
                proof: new OneOutOfManyProof(),
                err: new Error("the number of Commitment list's elements must be equal to CMRingSize")
            }
        }

        let n = constants.CMRingSizeExp;

        // Check indexIsZero
        if (this.indexIsZero > N) {
            return {
                proof: new OneOutOfManyProof(),
                err: new Error("Index is zero must be Index in list of commitments")
            }
        }

        // represent indexIsZero in binary
        let indexIsZeroBinary = utils.ConvertIntToBinary(this.indexIsZero, n);

        // randomness array
        let r = new Array(n);       // big int array
        let a = new Array(n);       // big int array
        let s = new Array(n);       // big int array
        let t = new Array(n);       // big int array
        let u = new Array(n);       // big int array

        let cl = new Array(n);       // elliptic point array
        let ca = new Array(n);       // elliptic point array
        let cb = new Array(n);       // elliptic point array
        let cd = new Array(n);       // elliptic point array

        for (let j = 0; j < n; j++) {
            // Generate random numbers
            r[j] = utils.RandInt();
            a[j] = utils.RandInt();
            s[j] = utils.RandInt();
            t[j] = utils.RandInt();
            u[j] = utils.RandInt();

            // convert indexIsZeroBinary[j] to big.Int
            let indexInt = new common.BigInt(indexIsZeroBinary[j]);

            // Calculate cl, ca, cb, cd
            // cl = Com(l, r)
            cl[j] = pc.PedCom.CommitAtIndex(indexInt, r[j], constants.SK);

            // ca = Com(a, s)
            ca[j] = pc.PedCom.CommitAtIndex(a[j], s[j], constants.SK);

            // cb = Com(la, t)
            let la = indexInt.mul(a[j]);
            cb[j] = pc.PedCom.CommitAtIndex(la, t[j], constants.SK)
        }

        // Calculate: cd_k = ci^pi,k
        for (let k = 0; k < n; k++) {
            // Calculate pi,k which is coefficient of x^k in polynomial pi(x)
            let iBinary = utils.ConvertIntToBinary(0, n);
            let pik = GetCoefficient(iBinary, k, n, a, indexIsZeroBinary);
            cd[k] = this.stmt.commitments[0].mul(pik);

            for (let i = 1; i < N; i++) {
                let iBinary = utils.ConvertIntToBinary(i, n);
                let pik = GetCoefficient(iBinary, k, n, a, indexIsZeroBinary);
                cd[k] = cd[k].add(this.stmt.commitments[i].mul(pik));
            }

            cd[k] = cd[k].add(pc.PedCom.CommitAtIndex(new common.BigInt(0), u[k], constants.SK))
        }

        // Calculate challenge x
        let x = new common.BigInt(0);

        for (let j = 0; j < n; j++) {
            x = zkpUtils.generateChallenge([x.toArray(), cl[j].compress(), ca[j].compress(), cb[j].compress(), cd[j].compress()]);
        }

        // Calculate za, zb zd
        let za = new Array(n);      // big int array
        let zb = new Array(n);      // big int array
        let f = new Array(n);      // big int array

        for (let j = 0; j < n; j++) {
            // f = lx + a
            let indexInt = new common.BigInt(indexIsZeroBinary[j]);
            f[j] = indexInt.mul(x);
            f[j] = f[j].add(a[j]);
            f[j] = f[j].umod(P256.n);

            // za = s + rx
            za[j] = r[j].mul(x);
            za[j] = za[j].add(s[j]);
            za[j] = za[j].umod(P256.n);

            // zb = r(x - f) + t
            zb[j] = x.sub(f[j]);
            zb[j] = zb[j].mul(r[j]);
            zb[j] = zb[j].add(t[j]);
            zb[j] = zb[j].umod(P256.n);
        }

        // zd = rand * x^n - sum_{k=0}^{n-1} u[k] * x^k
        let zd = x.pow(new common.BigInt(n));
        zd = zd.mul(this.rand);

        // let uxInt = new common.BigInt(0);
        let sumInt = new common.BigInt(0);
        for (let k = 0; k < n; k++) {
            let uxInt = x.pow(new common.BigInt(k));
            uxInt = uxInt.mul(u[k]);
            sumInt = sumInt.add(uxInt);
            sumInt = sumInt.umod(P256.n);
        }

        zd = zd.sub(sumInt);
        zd = zd.umod(P256.n);

        let proof = new OneOutOfManyProof();
        proof.set(this.stmt.commitments, cl, ca, cb, cd, f, za, zb, zd);

        return {
            proof: proof,
            err: null
        }
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
        this.stmt = new OneOutOfManyStatement();
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
        return this.stmt.commitments.length === 0
    }

    set(commitments, cl, ca, cb, cd, f, za, zb, zd) {
        this.stmt.commitments = commitments;
        this.cl = cl;
        this.ca = ca;
        this.cb = cb;
        this.cd = cd;
        this.f = f;
        this.za = za;
        this.zb = zb;
        this.zd = zd;
        return this;
    }

    toBytes() {
        // if proof is null, return an empty array
        if (this.isNull()) {
            return [];
        }

        let bytes = new Uint8Array(constants.OneOfManyProofSize);
        let offset = 0;

        // N = 2^n
        let N = constants.CMRingSize;
        let n = constants.CMRingSizeExp;

        // convert array cl to bytes array
        for (let i = 0; i < n; i++) {
            bytes.set(this.cl[i].compress(), offset);
            offset += constants.CompressPointSize;
        }
        // convert array ca to bytes array
        for (let i = 0; i < n; i++) {
            bytes.set(this.ca[i].compress(), offset);
            offset += constants.CompressPointSize;
        }

        // convert array cb to bytes array
        for (let i = 0; i < n; i++) {
            bytes.set(this.cb[i].compress(), offset);
            offset += constants.CompressPointSize;
        }

        // convert array cd to bytes array
        for (let i = 0; i < n; i++) {
            bytes.set(this.cd[i].compress(), offset);
            offset += constants.CompressPointSize;
        }

        // convert array f to bytes array
        for (let i = 0; i < n; i++) {
            bytes.set(this.f[i].toArray('be', constants.BigIntSize), offset);
            offset += constants.BigIntSize;
        }

        // convert array za to bytes array
        for (let i = 0; i < n; i++) {
            bytes.set(this.za[i].toArray('be', constants.BigIntSize), offset);
            offset += constants.BigIntSize;
        }

        // convert array zb to bytes array
        for (let i = 0; i < n; i++) {
            bytes.set(this.zb[i].toArray('be', constants.BigIntSize), offset);
            offset += constants.BigIntSize;
        }

        bytes.set(this.zd.toArray('be', constants.BigIntSize), offset);
        return bytes;
    }
}

// Get coefficient of x^k in the polynomial p_i(x)
function GetCoefficient(iBinary, k, n, a, l) {
    let res = new poly.Poly([new common.BigInt(1)]);
    let fji = new poly.Poly([]);

    for (let j = n - 1; j >= 0; j--) {
        let fj = new poly.Poly([a[j], new common.BigInt(l[j])]);
        if (iBinary[j] === 0) {
            fji = new poly.Poly([new common.BigInt(0), new common.BigInt(1)]).Sub(fj, P256.n);
        } else {
            fji = fj;
        }
        res = res.Mul(fji, P256.n);
    }

    if (res.GetDegree() < k) {
        return new common.BigInt(0);
    }
    return res[k];
}

function TestOneOutOfMany() {

    let N = constants.CMRingSize;
    let n = constants.CMRingSizeExp;

    let commitments = new Array(N);
    for (let i = 0; i < N; i++) {
        commitments[i] = P256.randomize();
        console.log("commitment: ", i, commitments[i].compress().join(', '));
    }

    console.log();

    let indexIsZero = 3;
    let randIsZero = new common.BigInt(100);
    commitments[indexIsZero] = pc.PedCom.CommitAtIndex(0, randIsZero, constants.SK);

    let wit = new OneOutOfManyWitness();
    wit.set(commitments, randIsZero, indexIsZero);
    let proof = wit.prove();
    for (let i=0; i<n; i++){
        console.log("cl ", i, ": ", proof.proof.cl[i].compress().join(', '));
        console.log("ca ", i, ": ", proof.proof.ca[i].compress().join(', '));
        console.log("cb ", i, ": ", proof.proof.cb[i].compress().join(', '));
        console.log("cd ", i, ": ", proof.proof.cd[i].compress().join(', '));
        console.log("f ", i, ": ", proof.proof.f[i].toArray().join(', '));
        console.log("za ", i, ": ", proof.proof.za[i].toArray().join(', '));
        console.log("zb ", i, ": ", proof.proof.zb[i].toArray().join(', '));

        console.log("commitments ", i, ": ", proof.proof.stmt.commitments[i].compress().join(', '));
        console.log();
        console.log();
    }
    console.log("zd : ", proof.proof.zd.toArray().join(', '));

    // console.log("Proof struct: ", proof.proof);
    console.log("Proof byte: ", proof.proof.toBytes().join(', '));
    console.log("Proof byte len: ", proof.proof.toBytes().length);


}

TestOneOutOfMany();


module.exports = {OneOutOfManyWitness, OneOutOfManyProof};
