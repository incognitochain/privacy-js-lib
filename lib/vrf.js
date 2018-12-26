var common = require("./common");
var ec = require("./ec.js");

// Eval returns a pseudo-random elliptic curve point P = F(seed, derivator), where
// F is a pseudo-random function defined by F(x, y) = 1/(x + y)*G, where x, y are integers,
// seed and derivator are integers of size at least 32 bytes,
// G is a generating point of the group of points of an elliptic curve.
function Eval(seed, derivator, generator) {
    if (!ec.IsSafe(generator)) {
        return null;
    }
    return generator.mul((seed.toRed(ec.moduleN).redAdd(derivator.toRed(ec.moduleN))).redInvm().fromRed());
}

module.exports = { Eval };