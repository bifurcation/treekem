'use strict';

const cs = window.crypto.subtle;
const EC = require('elliptic').ec;
const BN = require('bn.js');
const base64 = require('./base64');

const p256 = new EC('p256');

const ENDIAN = 'be';
const INTLEN = 32;

function bn2b64(n) {
  const bytes = n.toArray(ENDIAN, INTLEN);
  let base64 = (new Buffer(bytes)).toString('base64');
  return base64.replace(/=/g, '')
               .replace(/\+/g, '-')
               .replace(/\//g, '_');
}

async function iota(secret64) {
  // Digest the input
  const secret = base64.parse(secret64);
  const salg = {
    name: "HKDF",
    hash: "SHA-256",
    salt: Buffer.from("iota"),
    info: Buffer.alloc(0)
  };
  const skey = await cs.importKey("raw", secret, salg, false, ["deriveBits"]);
  const digest = await cs.deriveBits(salg, skey, 256);

  // Convert it to an integer and compute the resulting key pair
  const arr = Array.from(new Uint8Array(digest));
  const hex = arr.map(x => ('0' + x.toString(16)).slice(-2)).join("");
  const bnD = new BN(hex, 16);
  const keyPair = p256.keyFromPrivate(bnD);
  keyPair.getPublic();
  
  // Build JWKs
  const d = bn2b64(bnD);
  const x = bn2b64(keyPair.pub.x.fromRed());
  const y = bn2b64(keyPair.pub.y.fromRed());
  const privJWK = {kty: "EC", crv: "P-256", x: x, y: y, d: d};
  const pubJWK = {kty: "EC", crv: "P-256", x: x, y: y};

  const alg = {
    name: "ECDH",
    namedCurve: "P-256",
  }; 
  return {
    privateKey: privJWK,
    publicKey: pubJWK,
  }
}

module.exports = iota;
