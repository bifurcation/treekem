'use strict';

const TKEM = require('./tkem').class;

class TKEMState {
  constructor() {
    this.tkem = new TKEM();
  }

  get index() {
    return this.tkem.index;
  }

  get size() {
    return this.tkem.size;
  }

  get nodes() {
    return this.tkem.nodes;
  }

  async equal(other) {
    return this.tkem.equal(other.tkem);
  }
  
  static async oneMemberGroup(leaf) {
    let state = new TKEMState();
    state.tkem = await TKEM.oneMemberGroup(leaf);
    return state;
  }

  static async fromGroupAdd(initPriv, groupAdd) {
    let leaf = await ECKEM.decrypt(groupAdd.forJoiner.encryptedLeaf, initPriv);
    let state = new TKEMState();
    state.tkem = await TKEM.fromFrontier(groupAdd.forJoiner.size, groupAdd.forJoiner.frontier, leaf);
    return state;
  }

  static async fromUserAdd(leaf, /* IGNORED */ userAdd, groupInitKey) {
    let state = new TKEMState();
    state.tkem = await TKEM.fromFrontier(groupInitKey.size, groupInitKey.frontier, leaf);
    return state;
  }

  static async join(leaf, groupInitKey) {
    let tkem = await TKEM.fromFrontier(groupInitKey.size, groupInitKey.frontier, leaf);
    let ct = await tkem.encrypt(leaf)
    return {
      ciphertexts: ct.ciphertexts,
      nodes: ct.nodes,
    };
  }

  async add(userInitPub) {
    let leaf = window.crypto.getRandomValues(new Uint8Array(32));
    let encryptedLeaf = await ECKEM.encrypt(leaf, userInitPub);
    let ua = await TKEMState.join(leaf, this.groupInitKey);
    return {
      forGroup: ua,
      forJoiner: {
        size: this.tkem.size,
        frontier: this.tkem.frontier(),
        encryptedLeaf: encryptedLeaf,
      },
    };
  }

  async update(leaf) {
    let ct = await this.tkem.encrypt(leaf);
    return {
      from: this.tkem.index,
      ciphertexts: ct.ciphertexts,
      nodes: ct.nodes,
    }
  }
  
  remove(index) {/* TODO */}

  get groupInitKey() {
    return {
      size: this.tkem.size,
      frontier: this.tkem.frontier(),
    };
  }

  async handleUserAdd(ua) {
    let pt = await this.tkem.decrypt(this.tkem.size, ua.ciphertexts);
    this.tkem.merge(ua.nodes);
    this.tkem.merge(pt.nodes);
    this.tkem.size += 1;
  }

  async handleGroupAdd(ga) {
    let pt = await this.tkem.decrypt(this.tkem.size, ga.forGroup.ciphertexts);
    this.tkem.merge(ga.forGroup.nodes);
    this.tkem.merge(pt.nodes);
    this.tkem.size += 1;
  }

  async handleSelfUpdate(/* IGNORED */ update, leaf) {
    let privateNodes = await TKEM.hashUp(2*this.tkem.index, this.tkem.size, leaf);
    this.tkem.merge(privateNodes);
  }

  async handleUpdate(update) {
    let pt = await this.tkem.decrypt(update.from, update.ciphertexts);
    this.tkem.merge(update.nodes);
    this.tkem.merge(pt.nodes);
  }
  
  handleRemove(remove) {/* TODO */}
}

module.exports = TKEMState;
