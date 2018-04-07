'use strict';

const ECKEM = require('./eckem');
const iota = require('./iota');
const tm = require('./tree-math');
const cs = window.crypto.subtle;

function hash(x) {
  return cs.digest("SHA-256", x);
}

class TKEM {
  constructor(/* TODO */) {
    this.size = 0;
    this.index = 0;
    this.nodes = [];
  }

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
   *     // Public nodes along the direct path
   *     nodes: { Int: Node }
   *
   *     // Private nodes along the direct path
   *     privateNodes: { Int: Node }
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
    let nodes = {};
    let privateNodes = {};
    let ciphertexts = [];
    for (let i = 0; i < dirpath.length; ++i) {
      let kp = await iota(h);
      nodes[dirpath[i]] = { public: kp.publicKey };
      privateNodes[dirpath[i]] = {
        public: kp.publicKey,
        private: kp.privateKey,
      };

      h = await hash(h); 
      ciphertexts[i] = await ECKEM.encrypt(h, this.nodes[copath[i]].public);
    }

    return {
      root: h,
      index: this.index,
      nodes: nodes,
      privateNodes: privateNodes,
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
   *     // Public nodes resulting from hashes on the direct path
   *     nodes: { Int: Node }
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
    let nodes = {};
    let root = tm.root(this.size);
    let hashPath = dirpath.slice(dirIndex+1);
    hashPath.push(root);
    for (const n of hashPath) {
      let keyPair = await iota(h);
      nodes[n] = {
        secret: h,
        private: keyPair.privateKey,
        public: keyPair.publicKey,
      }
      h = await hash(h);
    }

    return {
      root: nodes[root].secret,
      nodes: nodes,
    }
  }

  /*
   * Updates nodes in the tree.
   *
   * Arguments:
   *   nodes - Dictionary of nodes to udpate: { Int: Node }
   *
   * Returns: None
   */
  merge(nodes) {
    for (let n in nodes) {
      this.nodes[n] = nodes[n];
    }
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

  // Values you should see on inspection:
  // h^0 = 00010203
  // h^1 = 054edec1d0211f624fed0cbca9d4f9400b0e491c43742af2c5b0abebf0c990d8
  // h^2 = f7a355c00c89a08c80636bed35556a210b51786f6803a494f28fc5ba05959fc2
  // h^3 = b4e844306e22060209c2f63956ab8bd5266cb548472d6773ebb41eb5bd700173
  // h^4 = 858b98df0255fbd305d9b772e19159e3f92b5ed7a458c549040f4d6331b5ea19 <-- too far
  let seed = new Uint8Array([0,1,2,3]);
  let keyPairs = await Promise.all([...Array(nodeWidth).keys()].map(i => iota(new Uint8Array([i]))));
  let nodes = {}
  keyPairs.map((kp, i) => { 
    nodes[i] = {
      private: kp.privateKey, 
      public: kp.publicKey 
    };
  });
  
  // Provision members
  let members = [];
  for (let i = 0; i < size; ++i) {
    members[i] = new TKEM();
    members[i].size = size;
    members[i].index = i;

    // Public keys along its copath
    for (const n of tm.copath(2*i, size)) {
      members[i].nodes[n] = {
        public: nodes[n].public,
      };
    }

    // Private keys along its direct path
    for (const n of tm.dirpath(2*i, size)) {
      members[i].nodes[n] = {
        private: nodes[n].private,
      };
    }
  }

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

      // Merge public values, then private
      m2.merge(ct.nodes);
      m2.merge(pt.nodes);
    }

    m.merge(ct.privateNodes);
  }

  console.log("[tkem-encrypt-decrypt] PASS");
}

module.exports = {
  class: TKEM,
  test: test,
};
