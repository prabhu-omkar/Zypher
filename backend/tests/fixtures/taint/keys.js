const crypto = require("crypto");

// A module-level const is not resolved through a wrapper in JavaScript, so the
// resolved case below passes a literal. See
// test_taint_scanner.py::test_module_level_constants_are_a_known_boundary.
const LEGACY_BITS = 1024;

function buildPair(bits) {
  return crypto.generateKeyPairSync("rsa", { modulusLength: bits });
}

function legacyPair() {
  return buildPair(1024);
}

function constPair() {
  return buildPair(LEGACY_BITS);
}

function digest(name, data) {
  return crypto.createHash(name).update(data).digest();
}

function legacyDigest(data) {
  return digest("md5", data);
}

function curve(name) {
  return crypto.createECDH(name);
}

function weakCurve() {
  return curve("secp160r1");
}

module.exports = { legacyPair, constPair, legacyDigest, weakCurve };
