'use strict';

const base64 = require('./base64');
const cs = window.crypto.subtle;

const ECDH_KEY_USAGES = ["deriveBits", "deriveKey"];
const ECDH_GEN = { name: "ECDH", namedCurve: "P-256" };
const SECRET_BITS = 256;

async function _import(jwk) {
  // XXX(rlb@ipv.sx): Firefox appears not to set this properly on export
  jwk.key_ops = ECDH_KEY_USAGES;
  return await cs.importKey("jwk", jwk, ECDH_GEN, true, ["deriveBits"]);
}

async function _export(pub) {
  return cs.exportKey("jwk", pub)
}

/*
 * Arguments: None
 *
 * Returns: Promise resolving to:
 *   {
 *     privateKey: CryptoKey,
 *     publicKey: CryptoKey,
 *   }
 */
async function newKeyPair() {
  const kp = await cs.generateKey(ECDH_GEN, true, ECDH_KEY_USAGES);
  return {
    privateKey: await _export(kp.privateKey),
    publicKey: await _export(kp.publicKey),
  };
}

/*
 * Arguments:
 *   priv: CryptoKey representing a DH private key
 *   pub: CryptoKey representing a DH public key
 *
 * Returns: Promise resolving to ArrayBuffer
 */
async function secret(privJWK, pubJWK) {
  const priv = await _import(privJWK);
  const pub = await _import(pubJWK);
  const alg = { 
    name: "ECDH", 
    namedCurve: "P-256", 
    public: pub,
  };

  const ss = await cs.deriveBits(alg, priv, SECRET_BITS);
  return base64.stringify(ss);
}

/*
 * Arguments:
 *   pub: CryptoKey representing a DH public key
 *
 * Returns: Promise resolving to a string with the hex SHA-256 hash
 * of the SPKI representation of the public key.
 */
async function fingerprint(pubJWK) {
  const pub = await _import(pubJWK);
  const spki = await cs.exportKey("spki", pub);
  const digest = await cs.digest("SHA-256", spki);
  return base64.stringify(digest);
}

/*
 * Self-test: DH exchange
 */
async function test() {
  const base64 = require("./base64");

  try {
    console.log("newKP...");
    const kpA = await newKeyPair();
    const kpB = await newKeyPair();

    console.log("secret...");
    const ssAB = await secret(kpA.privateKey, kpB.publicKey);
    const ssBA = await secret(kpB.privateKey, kpA.publicKey);
    
    console.log("[DH]", (ssAB == ssBA)? "PASS" : "FAIL");
  } catch (err) {
    console.log("[DH] FAIL:", err);
  }
}

module.exports = {
  newKeyPair: newKeyPair,
  secret: secret,
  fingerprint: fingerprint,
  test: test,
}
