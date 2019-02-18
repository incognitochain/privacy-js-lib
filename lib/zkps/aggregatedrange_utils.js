let common = require("../common");
let utils = require('../privacy_utils');
let zkp_utils = require('./utils');
let pedCom = require('../pedersen');
let constant = require('../constants');
let P256 = new common.Elliptic('p256');
let ZeroPoint = P256.curve.point(0, 0);
let aggparams = require("./aggregaterangeparams");
class InnerProductWitness {
    constructor(){
        this.a = [];
        this.b = [];
        this.p = ZeroPoint
    }
    Prove(AggParam){
        if (this.a.length !== this.b.length){
            return null
        }
        let n = this.a.length;
        let a = [];
        let b = [];
        for (let i=0;i<n;i++){
            a[i] = this.a[i];
            b[i] = this.b[i];
        }
        let p = P256.curve.point(this.p.getX(), this.p.getY());
        let G = [];
        let H = [];
        for (let i = 0;i<n;i++){
            G[i] = P256.curve.point(AggParam.G[i].getX(), AggParam.G[i].getY());
            H[i] = P256.curve.point(AggParam.H[i].getX(), AggParam.H[i].getY());
        }
        let proof = new InnerProductProof();
        proof.l = [];
        proof.r = [];
        proof.p = this.p;
        while (n>1){
            let nPrime = n/2;
            let cL = InnerProduct(a.slice(0,nPrime), b.slice(nPrime,));
            let cR = InnerProduct(a.slice(nPrime,), b.slice(0,nPrime));
            let L = aggparams.EncodeVectors(a.slice(0,nPrime), b.slice(nPrime,), G.slice(nPrime,), H.slice(0,nPrime));
            L = L.add(AggParam.U.mul(cL));
            proof.l = proof.l.concat(L);
            let R  = aggparams.EncodeVectors(a.slice(nPrime,), b.slice(0,nPrime), G.slice(0,nPrime), H.slice(nPrime,));
            R = R.add(AggParam.U.mul(cR));
            proof.r = proof.r.concat(R);
            // calculate challenge x = hash(G || H || u || p ||  l || r)
            let values = [];
            values[0] = p.compress();
            values[1] = L.compress();
            values[2] = R.compress();
            let x = aggparams.generateChallengeForAggRange(AggParam,values);
            let xInverse = x.invm(P256.n);
            let GPrime = [];
            let HPrime = [];
            for (let i=0;i<nPrime;i++){
                GPrime[i] = G[i].mul(xInverse).add(G[i+nPrime].mul(x));
                HPrime[i] = H[i].mul(x).add(H[i+nPrime].mul(xInverse));
            }
            let xSquare = x.mul(x);
            let xSquareInverse = xSquare.invm(P256.n);
            let PPrime = L.mul(xSquare).add(p).add(R.mul(xSquareInverse));

            // calculate aPrime, bPrime
            let aPrime = [];
            let bPrime = [];

            for (let i=0;i< nPrime;i++){
                aPrime[i] = a[i].mul(x);
                aPrime[i] = aPrime[i].add(a[i+nPrime].mul(xInverse));
                aPrime[i] = aPrime[i].umod(P256.n);

                bPrime[i] = b[i].mul(xInverse);
                bPrime[i] = bPrime[i].add(b[i+nPrime].mul (x));
                bPrime[i] = bPrime[i].umod(P256.n);
            }

            a = aPrime;
            b = bPrime;
            p = P256.curve.point(PPrime.getX(), PPrime.getY());
            G = GPrime;
            H = HPrime;
            n = nPrime;
        }

        proof.a = a[0];
        proof.b = b[0];
        return proof
    }
}
class InnerProductProof {
    constructor() {
        this.l = [];
        this.r = [];
        this.a = new common.BigInt("0");
        this.b = new common.BigInt("0");
        this.p = P256.curve.point(0, 0);
    }
    Bytes(){
        let l = 1 + constant.CompressPointSize*(this.l.length+this.r.length) + 2*constant.BigIntSize + constant.CompressPointSize;
        let bytes = new Uint8Array(l);
        let offset = 0;
        bytes.set([this.l.length],offset);
        offset++;
        for (let i=0;i<this.l.length;i++){
            bytes.set(this.l[i].compress(),offset);
            offset+=constant.CompressPointSize;
        }
        for (let i=0;i<this.r.length;i++){
            bytes.set(this.r[i].compress(),offset);
            offset+=constant.CompressPointSize;
        }
        bytes.set(this.a.toArray("be",constant.BigIntSize),offset);
        offset+=constant.BigIntSize;
        bytes.set(this.b.toArray("be",constant.BigIntSize),offset);
        offset+=constant.BigIntSize;
        bytes.set(this.p.compress(), offset);
        return bytes
    }
}
function InnerProduct(a, b) {
    if (a.length !== b.length){
        return null
    }

    let c = new common.BigInt("0", 10);
    for (let i = 0;i< a.length;i++) {
        let tmp = a[i].mul(b[i]);
        c = c.add(tmp);
    }
    c = c.umod(P256.n);
    return c;
}
function VectorAdd(v,w){
    if(v.length!==w.length){
        return null
    }
    let result = [];
    for (let i=0;i< v.length;i++){
        result[i] = v[i].add(w[i]);
        result[i] = result[i].umod(P256.n)
    }
    return result
}
function HadamardProduct(v, w) {
    if (v.length !== w.length) {
        //privacy.NewPrivacyErr(privacy.UnexpectedErr, errors.New("HadamardProduct: Uh oh! Arrays not of the same length"))
    }

    let result = [];

    for (let i=0;i< v.length;i++){
        result[i] = v[i].mul(w[i]);
        result[i] = result[i].umod(P256.n);
    }
    return result
}
function VectorAddScalar(v, s){
    result = [];
    for (let i=0;i < v.length;i++) {
        result[i] = v[i].add(s);
        result[i] = result[i].umod(P256.n);
    }
    return result
}
function VectorMulScalar(v,s) {
    result = [];
    for (let i=0;i< v.length;i++){
        result[i] = v[i].mul(s);
        result[i] = result[i].umod(P256.n);
    }
    return result
}
function PadLeft(str,pad,l){
    let strCopy = str;
    while (strCopy.length < l){
        strCopy = pad + strCopy
    }
    return strCopy
}
function StrToBigIntArray(str){
    result = [];
    for (let i=0;i<str.length;i++){
        result[i] = new common.BigInt(str[i],10);
    }
    return result
}
function reverse(arr) {
    let result = [];
    let leng = arr.length;
    for(let i=0;i< arr.length; i++){
        result[i] = arr[leng-i-1]
    }
    return result
}
function PowerVector(base,l) {
    let result = [];
    result[0] = new common.BigInt("1");
    for(let i=1;i<l;i++){
        result[i] = base.mul(result[i-1]);
        result[i] = result[i].umod(P256.n);
    }
    return result;
}
function RandVector(l){
    let result = [];
    for (let i=0;i<l;i++){
        x = utils.RandInt(32);
        x = x.umod(P256.n);
        result[i] = x
    }
    return result
}
function VectorSum(y) {
    result = new common.BigInt("0",10);
    for (let j=0;j< y.length;j++){
        result = result.add(new common.BigInt(j));
        result = result.umod(P256.n)
    }
    return result
}
function TwoVectorPCommitWithGens(G, H , a, b ) {
    if (G.length!== H.length || G.length!== a.length|| a.length !== b.length) {
        return null
    }
    let commitment = ZeroPoint;
    for (let i = 0; i < G.length; i++) {
        let modA = a[i].umod(P256.n);
        let modB = b[i].umod(P256.n);
        commitment = commitment.add(G[i].mul(modA)).add(H[i].mul(modB));
    }
    return commitment
}
function Pad(l){
    let deg = 0;
    while (l > 0) {
        if (l%2===0){
            deg++;
            l = l>>1;
        } else{
            break;
        }
    }
    let i = 0;
    for (;;){
        if (Math.pow(2,i)<l){
            i++;
        }else{
            l = Math.pow(2,i+deg);
            break;
        }
    }
    return l;

}
function DeltaMRP(y , z, m , rangeProofParams) {
    result = new common.BigInt("0");
    let z2 = z.mul(z);
    z2 = z2.umod(P256.n);
    let t1 = z.sub(z2);
    t1 = t1.umod(P256.n);
    let t2 = t1.mul(VectorSum(y));
    t2 = t2.umod(P256.n);
    let po2sum = new common.BigInt("2").pow(new common.BigInt(rangeProofParams.V/m));
    po2sum.umod(P256.n);
    po2sum = po2sum.sub(new common.BigInt("1",10));
    let t3 = new common.BigInt("0");
    for (let j=0;j<m;j++){
        let tmp = z.pow(new common.BigInt(3+j));
        tmp.umod(P256.n);
        t3 = t3.add(tmp);
    }
    t3.umod(P256.n);
    result = t2.sub(t3);
    result.umod(P256.n);
    return result
}
function CalculateLMRP(aL, sL , z, x){
    return VectorAdd(VectorAddScalar(aL, z.neg()),VectorMulScalar(sL,x));
}
function CalculateRMRP(aR, sR, y, zTimesTwo, z, x ) {
    if ((aR.length !== sR.length) || (aR.length !== y.length) || (y.length !== zTimesTwo.length)) {
        return null
    }
    return VectorAdd(HadamardProduct(y, VectorAdd(VectorAddScalar(aR, z), VectorMulScalar(sR, x))), zTimesTwo)
}
module.exports = {InnerProductWitness , Pad ,PowerVector,reverse,StrToBigIntArray,PadLeft,VectorAddScalar,TwoVectorPCommitWithGens,RandVector,
    VectorMulScalar, VectorAdd, HadamardProduct,DeltaMRP,InnerProduct,CalculateLMRP, CalculateRMRP, InnerProductProof};
//
// // x = new CryptoParams().InitCryptoParams(5,64);
// // console.log(x);
// // a = new common.BigInt("112903417795660718437322609784741174137436221623070734970718620502234785130587",10);
// // x= a.toString(10,null);
// // x = a.toBuffer("be", 77)
// // console.log(stringToBytes(x));
// // b = new common.BigInt("492",10);
// // console.log(b.toString(10,null));
// // y = b.toBuffer("be", 32)
// // console.log(y);
// // z = Buffer.concat([x,y]);
// // console.log(common.HashBytesToBytes(z));
//
// // a = new common.BigInt("47515829744028368076079098769021912108834233286729163024982797332997787453512",10);
// // b = new common.BigInt("87002542642193967023996021196060015663269581560271645134905725961626816885860",10);
// // c = new common.BigInt("43649401850892143763726554215752408353114045232054668349034459406587646176686",10);
// // d = new common.BigInt("70610724445527920943403872361121863038966490300463643114484538886656446460160",10);
// // z = a.toString(10,null) + b.toString(10,null)+c.toString(10,null)+d.toString(10,null)
// // console.log(common.HashBytesToBytes(utils.stringToBytes(z)));
// // z = [148, 5, 25, 99, 19, 192, 184, 176, 81, 215, 221, 166, 179, 63, 185, 72, 45 ,126, 121, 90 ,68 ,199, 98, 36, 112, 37, 112, 87, 25, 121, 43, 231]
// // console.log(utils.ByteArrToInt(z).toString(10,null));
// // let x = 5
// // a = new common.BigInt(x);
// // b = a.add(new common.BigInt('3'));
// // console.log(a.toString(10,null),a.add(new common.BigInt('3')).toString(10,null));