'use strict';

const cs = window.crypto.subtle;
const DH = require('./dh');

function AES_GCM_ENC(iv) {
  return { 
    name: "AES-GCM", 
    iv: iv || crypto.getRandomValues(new Uint8Array(12)),
  };
}

/*
 * Arguments:
 *   plaintext: The value to be encrypted, as a BufferSource
 *   pub:       Public key for the receiver
 *
 * Returns: Promise resolving to an ECKEMCiphertext object:
 *   {
 *     pub: CryptoKey
 *     iv: BufferSource
 *     ct: BufferSource
 *   }
 */
async function encrypt(plaintext, pubA) {
  const kpE = await DH.newKeyPair();
  const ekData = await DH.secret(kpE.privateKey, pubA);
  const ek = await cs.importKey("raw", ekData, "AES-GCM", false, ['encrypt']);

  const iv = window.crypto.getRandomValues(new Uint8Array(12))
  const alg = { name: "AES-GCM", iv: iv };
  const ct = await cs.encrypt(alg, ek, plaintext);

  return {
    pub: kpE.publicKey,
    iv: iv,
    ct: ct,
  };
}

/*
 * Arguments:
 *   ciphertext: The value to be decrypted, as an object
 *   priv:       Private key for the receiver
 *
 * Returns: Promise<ArrayBuffer>
 */
async function decrypt(ciphertext, priv) {
  const ekData = await DH.secret(priv, ciphertext.pub);
  const ek = await cs.importKey("raw", ekData, "AES-GCM", false, ['decrypt']);

  const alg = { name: "AES-GCM", iv: ciphertext.iv };
  return cs.decrypt(alg, ek, ciphertext.ct);
}

/*
 * Self-test: Encrypt/decrypt round trip
 */
async function test() {
  const original = new Uint8Array([0,1,2,3]);
  const kp = await DH.newKeyPair();

  try {
    const encrypted = await encrypt(original, kp.publicKey);
    const decrypted = await decrypt(encrypted, kp.privateKey);
    const equal = (Array.from(decrypted).filter((x,i) => (original[i] != x)).length == 0)
    console.log("[ECKEM]", equal? "PASS" : "FAIL");
  } catch (err) {
    console.log("[ECKEM] FAIL:", err);
  }
}

module.exports = {
  encrypt: encrypt,
  decrypt: decrypt,
  test: test,
}
