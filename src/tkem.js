'use strict';

const ECKEM = require('./eckem');
const iota = require('./iota');
const tm = require('./tree-math');
const cs = window.crypto.subtle;

const SVG = require('svg.js');

function hash(x) {
  return cs.digest("SHA-256", x);
}

const FADESTART = 80;
const FADESTOP = 20;

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
        secret: h,
        public: kp.publicKey,
        private: kp.privateKey,
      };

      if (dirpath[i] == tm.root(this.size)) {
        break;
      }

      h = await hash(h); 
      ciphertexts[i] = await ECKEM.encrypt(h, this.nodes[copath[i]].public);
    }

    // Add a node for the root, even though it's not needed
    let kp = await iota(h);
    let root = tm.root(this.size);
    nodes[root] = { public: kp.publicKey };
    privateNodes[root] = {
      secret: h,
      public: kp.publicKey,
      private: kp.privateKey,
    };

    // Assign a color and fade it back from the root
    let ha = Array.from(new Uint8Array(h));
    let hue = ha.reduce((x, y) => x ^ y);
    dirpath.push(root);
    let dl = Math.round((FADESTOP - FADESTART) / dirpath.length);
    for (let i = dirpath.length - 1; i >= 0; --i) {
      let l = FADESTART + i * dl;
      let color = `hsl(${hue}, 100%, ${l}%)`;
      
      let n = dirpath[i];
      privateNodes[n].color = color;
      if (nodes[n]) {
        nodes[n].color = color;
      }
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
    // These are the nodes that the sender encrypted to
    let senderSize = (index == this.size)? this.size + 1 : this.size;
    let copath = tm.copath(2 * index, senderSize);

    // These are the nodes that we should have private keys for
    let dirpath = tm.dirpath(2 * this.index, this.size);
    dirpath.push(tm.root(this.size));

    // Decrypt at the point where the dirpath and copath overlap
    let overlap = dirpath.filter(x => copath.includes(x))[0];
    let coIndex = copath.indexOf(overlap);
    let dirIndex = dirpath.indexOf(overlap);
    let h = await ECKEM.decrypt(ciphertexts[coIndex], this.nodes[overlap].private);

    // Hash up to the root (plus one if we're growing the tree)
    let nodes = {};
    let root = tm.root(this.size);
    let hashPath = dirpath.slice(dirIndex+1);
    if (senderSize > this.size) {
      root = tm.root(senderSize)
      hashPath.push(root);
    }

    for (const n of hashPath) {
      let keyPair = await iota(h);
      nodes[n] = {
        secret: h,
        private: keyPair.privateKey,
        public: keyPair.publicKey,
      }
      h = await hash(h);
    }

    // Assign a color and fade it back from the root
    let ha = Array.from(new Uint8Array(nodes[root].secret));
    let hue = ha.reduce((x, y) => x ^ y);
    dirpath.push(root);
    let dl = Math.round((FADESTOP - FADESTART) / dirpath.length);
    
    for (let i = dirpath.length - 1; i >= 0; --i) {
      let l = FADESTART + i * dl;
      let color = `hsl(${hue}, 100%, ${l}%)`;
      
      let n = dirpath[i];
      if (nodes[n]) {
        nodes[n].color = color;
      }
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

  /*
   * Returns the nodes on the frontier of the tree { Int: Node }
   */
  frontier() {
    let nodes = {};
    for (let n of tm.frontier(this.size)) {
      nodes[n] = this.nodes[n];
    }
    return nodes;
  }

  /*
   * Trees are equal if they have the same shape and they agree in
   * the nodes where they overlap.  Since there's no direct way to
   * test equality of CryptoKey objects, we export the public key
   * and check for equality of the exported octets.
   */
  async equal(other) {
    async function nodeEqual(a, b) {
      let spkiA = Array.from(new Uint8Array(await cs.exportKey("spki", a.publicKey)));
      let spkiB = Array.from(new Uint8Array(await cs.exportKey("spki", a.publicKey)));
      return spkiA.filter((x, i) => spkiB[i] == x).length == 0;
    }

    if (this.size != other.size) {
      return false;
    }

    for (let n of this.nodes) {
      if (this.nodes[n] && other.nodes[n] && !nodeEqual(this.nodes[n], other.nodes[n])) {
        return false;
      }
    }
    return true;
  }

  /********** SILLY DRAWING STUFF **********/

  /*
   * Draw an illustration of this tree as SVG into a <div>
   *
   * NB: Assumes:
   *   * `this.index` and `this.size` are set
   *   * No SVG is currently present in the indicated <div>
   */
  renderInit(id) {
    const root = tm.root(this.size);
    const height = tm.level(root);
    const width = tm.nodeWidth(this.size);
 
    const RECTRAD = 10;
    const RECTSIZE = 2 * RECTRAD;
    const RECTSPACE = 50;
    const STROKEWIDTH = 3;
 
    function center(n) {
      const h = tm.level(n);
      return {
        x: n * RECTSPACE + RECTRAD,
        y: (height - h) * RECTSPACE + RECTRAD,
      };
    }
 
    let index = [...Array(width).keys()];
    let nc = index.map(k => center(k));
    let pc = index.map(k => nc[tm.parent(k, this.size)]);

    this.svg = SVG(id).size(width * RECTSPACE, width * RECTSPACE);
    this.lines = index.map(k => {
      return this.svg.line(nc[k].x, nc[k].y, pc[k].x, pc[k].y)
                     .stroke({ width: STROKEWIDTH });
    });
    this.rects = index.map(k => {
      return this.svg.rect(RECTSIZE, RECTSIZE)
                     .cx(nc[k].x).cy(nc[k].y)
                     .stroke({ width: STROKEWIDTH });

    });

    return this;
  }

  async render() {
    const DEFAULTSTROKE = "hsl(0, 0%, 75%)";
    const DEFAULTFILL = "hsl(0, 0%, 100%)";

    async function hue(k) {
      let data = await cs.exportKey("spki", k);
      let hue = Array.from(new Uint8Array(data)).reduce((x, y) => x ^ y);
      return `hsl(${hue}, 100%, 50%)`;
    }

    let index = [...Array(this.rects.length).keys()];

    let stroke = await Promise.all(index.map(async k => {
      if (!this.nodes[k]) { 
        console.log("hue-select:", this.index, k, "default");
        return DEFAULTSTROKE;
      } else if (this.nodes[k].color) {
        console.log("hue-select:", this.index, k, "color", this.nodes[k].color);
        return this.nodes[k].color;
      } else {
        console.log("hue-select:", this.index, k, "public", await hue(this.nodes[k].public));
        return await hue(this.nodes[k].public);
      }

      return (!this.nodes[k])? DEFAULTSTROKE
           : (this.nodes[k].color)? this.nodes[k].color
           : await hue(this.nodes[k].public);
    }));
 
    let fill = index.map(k => {
      return (this.nodes[k] && this.nodes[k].private)? stroke[k] : DEFAULTFILL;
    });

    console.log(stroke, fill);

    this.lines.map((line, k) => { line.stroke(stroke[k]); });
    this.rects.map((rect, k) => { rect.fill(fill[k]).stroke(stroke[k]); });
  }
}

function arrayBufferEqual(a, b) {
  let ua = Array.from(new Uint8Array(a));
  let ub = Array.from(new Uint8Array(b));
  return ua.filter((x, i) => (ub[i] != x)).length == 0;
}

async function testMembers(size) {
  let nodeWidth = tm.nodeWidth(size);
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
  const root = tm.root(size);
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
    let dirpath = tm.dirpath(2*i, size);
    dirpath.push(root);
    for (const n of dirpath) {
      members[i].nodes[n] = {
        private: nodes[n].private,
        public: nodes[n].public,
      };
    }
  }

  return members;
}

async function testTwo() {
  // Initialize a one-node tree
  // XXX(RLB): This should just become the default ctor
  let m0 = new TKEM();
  m0.size = 1;
  let ct0 = await m0.encrypt(new Uint8Array([0]));
  m0.merge(ct0.privateNodes);

  // Initialize a second tree
  let m1 = new TKEM();
  m1.size = m0.size + 1;
  m1.index = m1.size - 1;
  m1.merge(m0.frontier());
  let ct1 = await m1.encrypt(new Uint8Array([1]));
  m1.merge(ct1.privateNodes);

  // Process the add at the first tree
  let pt1 = await m0.decrypt(ct1.index, ct1.ciphertexts);
  m0.merge(ct1.nodes);
  m0.merge(pt1.nodes);
  m0.size += 1;

  let eq = await m0.equal(m1);
  if (!eq) {
    window.m0 = m0;
    window.m1 = m1;
    throw 'tkem-user-add';
  }

  console.log("[tkem-user-add] PASS")
}

async function testUpdate() {
  const testGroupSize = 5;

  // Values you should see on inspection:
  // h^0 = 00010203
  // h^1 = 054edec1d0211f624fed0cbca9d4f9400b0e491c43742af2c5b0abebf0c990d8
  // h^2 = f7a355c00c89a08c80636bed35556a210b51786f6803a494f28fc5ba05959fc2
  // h^3 = b4e844306e22060209c2f63956ab8bd5266cb548472d6773ebb41eb5bd700173
  // h^4 = 858b98df0255fbd305d9b772e19159e3f92b5ed7a458c549040f4d6331b5ea19 <-- too far
  const seed = new Uint8Array([0,1,2,3]);

  // Create a group with the specified size
  let members = await testMembers(testGroupSize);

  // Have each member send and be received by all members
  for (const m of members) {
    let ct = await m.encrypt(seed);
    m.merge(ct.privateNodes);

    for (let m2 of members) {
      if (m2.index == m.index) {
        continue;
      }

      let pt = await m2.decrypt(ct.index, ct.ciphertexts);
      if (!arrayBufferEqual(ct.root, pt.root)) {
        console.log("error:", m.index, "->", m2.index);
        throw 'tkem-root';
      }

      // Merge public values, then private
      m2.merge(ct.nodes);
      m2.merge(pt.nodes);

      let eq = await m.equal(m2);
      if (!eq) {
        console.log("error:", m.index, "->", m2.index);
        throw 'tkem-eq';
      }
    }
  }

  console.log("[tkem-encrypt-decrypt] PASS");
}

module.exports = {
  class: TKEM,
  testMembers: testMembers,
  testUpdate: testUpdate,
  testTwo: testTwo,
};
