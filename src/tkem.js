'use strict';

const ECKEM = require('./eckem');
const iota = require('./iota');
const tm = require('./tree-math');
const cs = window.crypto.subtle;

function hash(x) {
  return cs.digest("SHA-256", x);
}

class TKEM {
  constructor(/* TODO */) {}

  /*
   * Encrypts a fresh root value in a way that all participants in
   * the group can decrypt (except for the current node).
   *
   * Arguments:
   *   * leaf - BufferSource with leaf secret
   *
   * Returns: Promise resolving to a TKEMCiphertext object:
   *   {
   *     // Index of the sender in the tree
   *     index: Int
   *
   *     // Public keys along the direct path
   *     publicKeys: [ CryptoKey ]
   *
   *     // Ciphertexts along the copath
   *     ciphertexts: [ ECKEMCiphertext ]
   *   }
   */
  async encrypt(leaf) {
    let dirpath = tm.dirpath(2 * this.index, this.size);
    let copath = tm.copath(2 * this.index, this.size);
    
    // Generate hashes up the tree
    // For each hash:
    // * convert to public key
    // * KEM to corresponding copath node
    let h = leaf;
    let hashes = [];
    let publicKeys = [];
    let ciphertexts = [];
    for (let i = 0; i < dirpath.length; ++i) {
      h = await hash(h); 
      hashes[i] = h;
      publicKeys[i] = (await iota(h)).publicKey;
      ciphertexts[i] = await ECKEM.encrypt(h, this.nodes[copath[i]].public);
    }

    return {
      root: hashes[hashes.length - 1],
      index: this.index,
      publicKeys: publicKeys,
      ciphertexts: ciphertexts,
    }; 
  }

  /*
   * Decrypts and returns fresh root value.
   *
   * Arguments:
   *   * index       - Index of sending node in the tree
   *   * ciphertexts - List of ECKEMCiphertexts along copath
   *
   * Returns: Promise resolving to an object:
   *   {
   *     // The root hash for the tree
   *     root: ArrayBuffer
   *
   *     // Hashes for other nodes
   *     hashes: { Int: ArrayBuffer }
   *   }
   */
  async decrypt(index, ciphertexts) {
    let dirpath = tm.dirpath(2 * this.index, this.size);
    let copath = tm.copath(2 * index, this.size);

    // Decrypt at the point where the dirpath and copath overlap
    let overlap = dirpath.filter(x => copath.includes(x))[0];
    let coIndex = copath.indexOf(overlap);
    let dirIndex = dirpath.indexOf(overlap);
    let h = await ECKEM.decrypt(ciphertexts[coIndex], this.nodes[overlap].private);

    // Hash up to the root
    let hashes = {};
    let root = tm.root(this.size);
    let hashPath = dirpath.slice(dirIndex+1);
    hashPath.push(root);
    for (const n of hashPath) {
      hashes[n] = h;
      h = await hash(h);
    }

    return {
      root: hashes[root],
      hashes: hashes,
    }
  }

  /*
   * Updates public keys along a path.
   *
   * Arguments:
   *   * index      - Index of sending node in the tree
   *   * publicKeys - List of CryptoKey values along direct path
   */
  update(index, publicKeys) {
    let dirpath = tm.dirpath(index, this.size);
    dirpath.map((n, i) => { this.nodes[n].public = publicKeys[i]; });
  }
}

function arrayBufferEqual(a, b) {
  let ua = Array.from(new Uint8Array(a));
  let ub = Array.from(new Uint8Array(b));
  return ua.filter((x, i) => (ub[i] != x)).length == 0;
}

async function test() {
  let size = 5;
  let nodeWidth = tm.nodeWidth(size);
  let members = [];
  for (let i = 0; i < size; ++i) {
    members[i] = new TKEM();
    members[i].size = size;
    members[i].index = i;
  }

  // Values you should see on inspection:
  // h^0 = 00010203
  // h^1 = 054edec1d0211f624fed0cbca9d4f9400b0e491c43742af2c5b0abebf0c990d8
  // h^2 = f7a355c00c89a08c80636bed35556a210b51786f6803a494f28fc5ba05959fc2
  // h^3 = b4e844306e22060209c2f63956ab8bd5266cb548472d6773ebb41eb5bd700173
  // h^4 = 858b98df0255fbd305d9b772e19159e3f92b5ed7a458c549040f4d6331b5ea19 <-- too far
  let seed = new Uint8Array([0,1,2,3]);
  let keyPairs = await Promise.all([...Array(nodeWidth).keys()].map(i => iota(new Uint8Array([i]))));
  let nodes = keyPairs.map(kp => { return { private: kp.privateKey, public: kp.publicKey }; });
  members.map(m => { m.nodes = nodes; });

  // Have each member send and be received by all members
  for (const m of members) {
    let ct = await m.encrypt(seed);

    for (let m2 of members) {
      if (m2.index == m.index) {
        continue;
      }

      let pt = await m2.decrypt(ct.index, ct.ciphertexts);
      if (!arrayBufferEqual(ct.root, pt.root)) {
        console.log("error:", m.index, "->", m2.index);
        throw 'tkem';
      }
    }
  }

  console.log("[tkem-encrypt-decrypt] PASS");
}

module.exports = {
  class: TKEM,
  test: test,
};
