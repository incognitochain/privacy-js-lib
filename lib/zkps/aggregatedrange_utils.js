var common = require("../common");
var utils = require('../privacy_utils');
var pedCom = require('../pedersen');
var constant = require('../constants');
var P256 = new common.Elliptic('p256');
var ZeroPoint = P256.curve.point(0, 0);
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
        this.U = ZeroPoint;
        this.V = 64;
        this.G = ZeroPoint;
        this.H = ZeroPoint;
    }
    NewECPrimeGroupKey(n){
        let gen1Vals = [];
        let gen2Vals = [];
        let u = ZeroPoint;
        let G = pedCom.PedCom.G[constant.VALUE];
        let H = pedCom.PedCom.G[constant.RAND];
        this.G = G;
        this.H = H;
        for (let i=0;i<n;i++){
            gen1Vals[i] = G.hash(0);
            G = G.hash(0);
            gen2Vals[i] = H.hash(0);
            H = H.hash(0);
        }
        u = G.add(H).hash(0);
        // cryptoParams = new CryptoParams();
        this.BPG = gen1Vals;
        this.BPH = gen2Vals;
        this.N = this.C.n;
        this.U = u;
        this.V = n;
    }
    InitCryptoParams(l,maxExp) {
        let vecLength = maxExp * Pad(l);
        this.NewECPrimeGroupKey(vecLength);
        return this
    }
}
function makeBigIntArray(l){
    result = [];
    for (let i=0;i<l+1;i++){
        result[i] = new common.BigInt("0");
    }
    return result
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
    x2 = x2.umod(P256.n);
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
    let data = L.getX().toString(10,null) + L.getY().toString(10,null)+R.getX().toString(10,null)+R.getY().toString(10,null);
    let s256 = common.HashBytesToBytes(utils.stringToBytes(data));
    let x = new common.BigInt(s256, 16, "be");
    proof.Challenges[curIt] = x;
    let Gprime, Hprime, Pprime = GenerateNewParams(G,H,x,L,R,P);
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
    }
    c = c.umod(P256.n);
    return c;
}
function VectorAdd(v,w){
    if(v.length!==w.length){
        // error
    }
    let result = [];
    for (let i=0;i<v.length;i++){
        result[i] = v[i].add(w[i]);
        result[i] = result[i].umod(P256.n)
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
function ScalarVectorMul(v,s) {
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
function PowerVector(l,base) {
    let result = [];
    for(let i=0;i<l;i++){
        result[i] = base.pow(new common.BigInt(i));
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
    result = new common.BigInt("0",10)
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
    for (var i = 0; i < G.length; i++) {
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
    return VectorAdd(VectorAddScalar(aL, z.neg()),ScalarVectorMul(sL,x));
}
function CalculateRMRP(aR, sR, y, zTimesTwo, z, x ) {
    if ((aR.length !== sR.length) || (aR.length !== y.length) || (y.length !== zTimesTwo.length)) {
        return null
    }
    return VectorAdd(VectorHadamard(y, VectorAdd(VectorAddScalar(aR, z), ScalarVectorMul(sR, x))), zTimesTwo)
}
module.exports = {InnerProdArg,CryptoParams,ZeroPoint , Pad ,PowerVector,reverse,StrToBigIntArray,PadLeft,VectorAddScalar,TwoVectorPCommitWithGens,RandVector,
VectorAdd,VectorHadamard,DeltaMRP,InnerProduct,CalculateLMRP, CalculateRMRP};

// x = new CryptoParams().InitCryptoParams(5,64);
// console.log(x);
// a = new common.BigInt("112903417795660718437322609784741174137436221623070734970718620502234785130587",10);
// x= a.toString(10,null);
// x = a.toBuffer("be", 77)
// console.log(stringToBytes(x));
// b = new common.BigInt("492",10);
// console.log(b.toString(10,null));
// y = b.toBuffer("be", 32)
// console.log(y);
// z = Buffer.concat([x,y]);
// console.log(common.HashBytesToBytes(z));

// a = new common.BigInt("47515829744028368076079098769021912108834233286729163024982797332997787453512",10);
// b = new common.BigInt("87002542642193967023996021196060015663269581560271645134905725961626816885860",10);
// c = new common.BigInt("43649401850892143763726554215752408353114045232054668349034459406587646176686",10);
// d = new common.BigInt("70610724445527920943403872361121863038966490300463643114484538886656446460160",10);
// z = a.toString(10,null) + b.toString(10,null)+c.toString(10,null)+d.toString(10,null)
// console.log(common.HashBytesToBytes(utils.stringToBytes(z)));
// z = [148, 5, 25, 99, 19, 192, 184, 176, 81, 215, 221, 166, 179, 63, 185, 72, 45 ,126, 121, 90 ,68 ,199, 98, 36, 112, 37, 112, 87, 25, 121, 43, 231]
// console.log(utils.ByteArrToInt(z).toString(10,null));
let x = 5
a = new common.BigInt(x);
b = a.add(new common.BigInt('3'));
console.log(a.toString(10,null),a.add(new common.BigInt('3')).toString(10,null));