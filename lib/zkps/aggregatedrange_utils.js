var common = require("../common");
var utils = require('../privacy_utils');
var pedCom = require('../pedersen');
var constant = require('../constants');
var P256 = new common.Elliptic('p256');
class InnerProdArg {
    constructor() {
        this.L = [];
        this.R = [];
        this.A = new common.BigInt("0");
        this.B = new common.BigInt("0");
        this.Challenges = [];
    }
}
class CryptoParams {
    constructor() {
        this.C = P256;
        this.BPG = [];
        this.BPH = [];
        this.N = new common.BigInt("0");
        this.U = ZeroPoint();
        this.V = 64;
        this.G = ZeroPoint();
        this.H = ZeroPoint();
    }
}
function makeBigIntArray(l){
    result = [];
    for (let i=0;i<l+1;i++){
        result[i] = new common.BigInt("0");
    }
    return result
}




function ZeroPoint() {
    return P256.curve.point(new common.BigInt("0"), new common.BigInt("0"))
}

function GenerateNewParams(G,H,x,L,R,P){
    let nprime = G.length/2;
    let Gprime = [];
    let Hprime = [];
    let xinv = x.invm(P256.n);
    for (let i=0;i<nprime;i++){
        Gprime[i] = G[i].mul(xinv).add(G[i+nprime].mul(x));
        Hprime[i] = H[i].mul(x).add(H[i+nprime].mul(xinv));
    }
    let x2 = x.mul(x);
    x2 = x2.mod(P256.n);
    let xinv2 = x.invm(P256.n);
    let Pprime = L.mul(x2).add(P).add(R.mul(xinv2));
    return [Gprime , Hprime , Pprime]
}
function InnerProductProveSub(proof, G, H, a, b, u, P){
    if  (a.length === 1) {
        proof.A = a[0];
        proof.B = b[0];
        return proof
    }
    curIt = Math.log2(a.length).toFixed(0)-1;
    nprime = a.length/2;
    let cl = InnerProduct(a.slice(0,nprime), b.slice(nprime,));
    let cr = InnerProduct();
    let L  = TwoVectorPCommitWithGens().add(u.mul(cl));
    let R  = TwoVectorPCommitWithGens().add(u.mul(cr));
    proof.L[curIt] = L;
    proof.R[curIt] = R;
    new common.BigInt("0").toString(10,"");
    let s256 = common.HashBytesToBytes(L.X.toString(10,"") + L.Y.toString(10,"")+R.X.toString(10,"")+R.Y.toString(10,""));
    let x = new common.BigInt(s256, 16, "be");
    proof.Challenges[curIt] = x;
    let Gprime, Hprime, Pprime = GenerateNewParams(G,H,x,L,R,P)
    xinv = x.invm(P256.n);
}











function InnerProduct(a, b) {
    if (a.length !== b.length){
       // privacy.NewPrivacyErr(privacy.UnexpectedErr, errors.New("InnerProduct: Uh oh! Arrays not of the same length"))
    }

    let c = new common.BigInt("0",10);
    for (let i = 0;i< a.length;i++) {
        let tmp = a[i].mul(b[i]);
        c = c.add(tmp);
        c = c.mod(P256.n);
    }
    return c
}
function VectorAdd(v,w){
    if(v.length!==w.length){
        // error
    }
    let result = [];
    for (let i=0;i<v.length;i++){
        result[i] = v[i].add(w[i]);
        result[i] = result[i].mod(P256.n)
    }
    return result
}
function VectorHadamard(v, w) {
    if (v.length !== w.length) {
        //privacy.NewPrivacyErr(privacy.UnexpectedErr, errors.New("VectorHadamard: Uh oh! Arrays not of the same length"))
    }

    let result = [];

    for (let i=0;i< v.length;i++){
        result[i] = v[i].mul(w[i]);
        result[i] = result[i].mod(P256.n);
    }
    return result
}
function VectorAddScalar(v, s){
    result = [];
    for (let i=0;i < v.length;i++) {
        result[i] = v[i].add(s);
        result[i] = result[i].mod(P256.n);
    }
    return result
}
function ScalarVectorMul(v,s) {
    result = [];
    for (let i=0;i< v.length;i++){
        result[i] = v[i].mul(s);
        result[i] = result[i].mod(P256.n);
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


// function StrToBigIntArray(str){
//     result = [];
//     for (let i=0;i<str.length;i++){
//         t, success
//     }
// }

function reverse(arr) {
    let result = [];
    let leng = arr.length;
    for(let i=0;i< arr.length; i++){
        result[i] = arr[leng-i-1]
    }
    return result
}
function PowerVector(l,base) {
    let result = [];

    for(let i=0;i<l;i++){
        result[i] = base.pow(new common.BigInt(i));
        result[i] = result[i].mod(P256.n);
    }
}
function RandVector(l){
    let result = [];
    for (let i=0;i<l;i++){
        x = utils.RandInt(32);
        x = x.mod(P256.n);
        result[i] = x
    }
    return result
}
function VectorSum(y) {
    result = new common.BigInt("0",10)
    for (let j=0;j<y.length;j++){
        result = result.add(j)
        result = result.mod(P256.n)
    }
    return result
}
function TwoVectorPCommitWithGens(G, H , a, b ) {
    if (G.length!== H.length || G.length!== a.length|| a.length !== b.length) {
        return null
    }
    let commitment = new P256.curve.point("0","0");
    for (var i = 0; i < len(G); i++) {
        let modA = a[i].mod(P256.n);
        let modB = b[i].mod(P256.n);
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
function NewECPrimeGroupKey(n){
    let gen1Vals = [];
    let gen2Vals = [];
    let u = ZeroPoint();
    let G = pedCom.PedCom.G[constant.VALUE];
    let H = pedCom.PedCom.G[constant.RAND];

    for (let i=0;i<n;i++){
        gen1Vals[i] = G.hash(0);
        G = G.hash(0);
        gen2Vals[i] = H.hash(0);
        H = H.hash(0);
    }
    u = G.add(H).hash(0);
    cryptoParams = new CryptoParams();
    cryptoParams.BPG = gen1Vals;
    cryptoParams.BPH = gen2Vals;
    cryptoParams.N = cryptoParams.C.n;
    cryptoParams.U = u;
    cryptoParams.V = n;
    cryptoParams.G = G;
    cryptoParams.H = H;
    return cryptoParams;
}
function InitCryptoParams(l,maxExp){
    let vecLength = maxExp * Pad(l);
    return new NewECPrimeGroupKey(vecLength);
}
module.exports = {InnerProdArg,Pad, InitCryptoParams, ZeroPoint};