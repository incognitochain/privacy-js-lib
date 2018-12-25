var common = require("./common");
var Curve = new common.Elliptic('p256');
var assert = require('assert')
var g1 = Curve.g;
var g2 = new common.BigInt("2",10);
var res = g1.mul(g2)
console.log("{", res.getX().toString(), "_", res.getY().toString(), "}");
