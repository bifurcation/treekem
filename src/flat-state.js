'use strict';

const DH = require('./dh');
const iota = require('./iota');
const util = require('./util');
const cs = window.crypto.subtle;

class FlatState {
  constructor() {
    this.index = 0;
    this.size = 1;
    this.nodes = [];
  }

  async _setOwnNode(leaf) {
    this.nodes[2 * this.index] = await util.newNode(leaf)
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
  
  async remove(index) {
    /* TODO */
    return {};
  }

  get groupInitKey() {
    let publicNodes = {};
    for (let n in this.nodes) {
      publicNodes[n] = util.publicNode(this.nodes[n]);
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
  
  async handleRemove(remove) {
    /* TODO */
  }
}

module.exports = FlatState;
