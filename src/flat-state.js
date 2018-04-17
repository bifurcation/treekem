'use strict';

const iota = require('./iota');
const cs = window.crypto.subtle;

// XXX(rlb@ipv.sx): Copied from tkem.js
async function fingerprint(pubKey) {
  const spki = await cs.exportKey("spki", pubKey);
  const digest = await cs.digest("SHA-256", spki);
  return hex(digest);
}

class FlatState {
  constructor() {
    this.index = 0;
    this.size = 1;
    this.nodes = {};
  }

  async equal(other) {
    let answer = (this.size == other.size);
    console.log("size", answer);

    for (let n in this.nodes) {
      let lfp = await fingerprint(this.nodes[n].public);
      let rfp = await fingerprint(other.nodes[n].public);
      answer = answer && (lfp == rfp);
      console.log("node", n, lfp == rfp);
    }

    return answer;
  }

  async dump(label) {
    console.log("=====", label, "=====");
    console.log("size:", this.size);
    console.log("index:", this.index);
    console.log("nodes:");
    for (let n in this.nodes) {
      if (!this.nodes[n]) {
        continue;
      }

      console.log("  ", n, ":", await fingerprint(this.nodes[n].public));
    }
  }  
  
  async _setOwnNode(leaf) {
    let kp = await iota(leaf);
    this.nodes[2 * this.index] = {
      secret: leaf,
      private: kp.privateKey,
      public: kp.publicKey,
    };
  }

  static async oneMemberGroup(leaf) {
    let state = new FlatState();
    await state._setOwnNode(leaf);
    return state;
  }

  static async fromGroupAdd(initLeaf, groupAdd) {
    let state = new FlatState();
    state.size = groupAdd.forJoiner.size + 1;
    state.index = groupAdd.forJoiner.size;
    state.nodes = groupAdd.forJoiner.nodes;
    await state._setOwnNode(initLeaf);
    return state;
  }

  static async fromUserAdd(leaf, /* IGNORED */ userAdd, groupInitKey) {
    let state = new FlatState();
    state.size = groupInitKey.size + 1;
    state.index = groupInitKey.size;
    state.nodes = groupInitKey.nodes;
    await state._setOwnNode(leaf);
    return state;
  }

  static async join(leaf, groupInitKey) {
    let kp = await iota(leaf);
    return kp.publicKey;
  }

  async add(userInitPub) {
    return {
      forJoiner: this.groupInitKey,
      forGroup: userInitPub,
    };
  }

  async update(leaf) {
    let kp = await iota(leaf);
    return {
      from: this.index,
      public: kp.publicKey,
    };
  }
  
  remove(index) {/* TODO */}

  get groupInitKey() {
    let publicNodes = {};
    for (let n in this.nodes) {
      publicNodes[n] = { public: this.nodes[n].public };
    }

    return {
      size: this.size,
      nodes: publicNodes,
    };
  }

  async handleUserAdd(ua) {
    this.nodes[2 * this.size] = { public: ua };
    this.size += 1;
  }

  async handleGroupAdd(ga) {
    this.nodes[2 * this.size] = { public: ga.forGroup };
    this.size += 1;
  }

  async handleSelfUpdate(/* IGNORED */ update, leaf) {
    await this._setOwnNode(leaf);
  }

  async handleUpdate(update) {
    this.nodes[2 * update.from].public = update.public;
  }
  
  handleRemove(remove) {/* TODO */}
}

module.exports = FlatState;
