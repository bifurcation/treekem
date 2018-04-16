'use strict';

const TKEM = require('./tkem').class;

class TKEMState {
  constructor() {
    this.tkem = new TKEM();
  }
  
  static async oneMemberGroup(leaf) {
    let state = TKEMState();
    state.tkem = TKEM.oneMemberGroup(leaf);
    return state;
  }

  static async fromGroupAdd(initPriv, groupAdd) {
    let leaf = await ECKEM.decrypt(groupAdd.forJoiner.encryptedLeaf, initPriv);
    let state = TKEMState();
    state.tkem = await TKM.fromFrontier(ga.forJoiner.size, ga.forJoiner.frontier, leaf);
    return state;
  }

  static async fromUserAdd(leaf, /* IGNORED */ userAdd, groupInitKey) {
    let state = TKEMState();
    state.tkem = TKEM.fromFrontier(groupInitKey.size, groupInitKey.frontier, leaf);
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
    let size = this.tkem.size;
    let frontier = this.tkem.frontier();
    let leaf = window.crypto.getRandomValues(new Uint8Array(32));
    let ua = await TKEM.userAdd(size, frontier, leaf);
    let encryptedLeaf = await ECKEM.encrypt(leaf, userInitPub);
    return {
      forGroup: {
        ciphertexts: ua.ciphertexts,
        nodes: ua.nodes,
      },
      forJoiner: {
        size: size,
        frontier: frontier,
        encryptedLeaf: encryptedLeaf,
      },
    };
  }

  update(leaf) {
    let ct = this.tkem.encrypt(leaf);
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
    let pt = await this.tkem.decrypt(this.tkem.size, ga.ciphertexts);
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

module.exports = {
  class: TKEMState,
  test: test,
};
