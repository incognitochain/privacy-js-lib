let P256 = require('../lib/ec').P256;
let BigInt = require('bn.js');
let assert = require('assert');
let cs = require('../lib/constants');
describe('Curve P256', function () {
    randomPoint = null;
    badPoint = null;
    before(function () {
        badPoint = P256.curve.point(new BigInt('82794344854243450371984501721340198645022926339504713863786955730156937886079', 10), new BigInt('335525218815814676708366178591785234073444719485138817189697292758', 10));
    });
    beforeEach(function () {
        randomPoint = P256.randomize();
    });
    it('Compress and decompress a random point', function () {
        assert.ok(randomPoint.isSafe(), "Test that result of randomize funtion is truly in P256");
        let decompressedPoint = P256.decompress(randomPoint.compress());
        assert.ok(randomPoint.eq(decompressedPoint), "Test that result of decompress function is true");
    });
    it('Get inverse of a given point and check it', function () {
        assert.ok(randomPoint.add(randomPoint.inverse()).isInfinity(), "Test that sum of a point and it's inversed is infinity");
    });
    it('A point which not safe on P256 is not accepted', function () {
        assert.ok(!badPoint.isSafe());
    });
    it('Marshall and Unmarshall a random point', function () {
        let tmp = cs.PRIVACY_VERSION;
        let marshaled = randomPoint.marshalJSON();
        let res = false;
        let err = null;
        try {
            res = randomPoint.eq(P256.unmarshalJSON(marshaled));
        } catch (error) {
            err = error;
            res = false;
        } finally {
            assert.ok(res, "Test marshall and unmarshall with normal value: " + err);
        }
        res = true;
        err = null;
        cs.PRIVACY_VERSION = 0x254;
        let badUnmarshaled = null;
        try {
            badUnmarshaled = P256.unmarshalJSON(randomPoint.marshalJSON());
            res = randomPoint.eq(badUnmarshaled);
        } catch (error) {
            err = error;
            res = false;
        } finally {
            assert.ok(!res, "Test marshall and unmarshall with wrong value: " + err);
        }
        cs.PRIVACY_VERSION = tmp;
    });
});