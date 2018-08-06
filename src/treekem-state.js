'use strict';

const TreeKEM = require('./treekem').class;

class TreeKEMState {
  constructor() {
    this.tkem = new TreeKEM();
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

  get copath() {
    return this.tkem.copath;
  }

  async equal(other) {
    return this.tkem.equal(other.tkem);
  }

  async dump() {
    return this.tkem.dump();
  }

  static fromJSON(obj) {
    let out = new TreeKEMState();
    out.tkem = TreeKEM.fromJSON(obj.tkem);
    return out;
  }
  
  static async oneMemberGroup(leaf) {
    let state = new TreeKEMState();
    state.tkem = await TreeKEM.oneMemberGroup(leaf);
    return state;
  }

  static async fromGroupAdd(initLeaf, groupAdd) {
    let kp = await iota(initLeaf);
    let leaf = await ECKEM.decrypt(groupAdd.forJoiner.encryptedLeaf, kp.privateKey);
    let state = new TreeKEMState();
    state.tkem = await TreeKEM.fromFrontier(groupAdd.forJoiner.size, groupAdd.forJoiner.frontier, leaf);
    return state;
  }

  static async fromUserAdd(leaf, /* IGNORED */ userAdd, groupInitKey) {
    let state = new TreeKEMState();
    state.tkem = await TreeKEM.fromFrontier(groupInitKey.size, groupInitKey.frontier, leaf);
    return state;
  }

  static async join(leaf, groupInitKey) {
    let tkem = await TreeKEM.fromFrontier(groupInitKey.size, groupInitKey.frontier, leaf);
    let ct = await tkem.encrypt(leaf, tkem.index)
    return {
      ciphertexts: ct.ciphertexts,
      nodes: ct.nodes,
    };
  }

  async add(userInitPub) {
    let leaf = base64.random(32);
    let encryptedLeaf = await ECKEM.encrypt(leaf, userInitPub);
    
    let gik = this.groupInitKey;
    let ua = await TreeKEMState.join(leaf, gik);

    return {
      forGroup: ua,
      forJoiner: {
        size: gik.size,
        frontier: gik.frontier,
        encryptedLeaf: encryptedLeaf,
      },
    };
  }

  async update(leaf) {
    let ct = await this.tkem.encrypt(leaf, this.tkem.index);
    return {
      from: this.tkem.index,
      ciphertexts: ct.ciphertexts,
      nodes: ct.nodes,
    }
  }
  
  async remove(leaf, index, copath) {
    this.tkem.merge(copath, true);
    let ct = await this.tkem.encrypt(leaf, index);
    return {
      index: index,
      ciphertexts: ct.ciphertexts,
      subtreeHeads: ct.subtreeHeads,
    };
  }

  async move(leaf, index, copath) {
    this.tkem.merge(copath, true);
    let ct = await this.tkem.encrypt(leaf, index);
    return {
      from: this.index,
      to: index,
      ciphertexts: ct.ciphertexts,
      nodes: ct.nodes,
      subtreeHeads: ct.subtreeHeads,
    };
  }

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
    let privateNodes = await TreeKEM.hashUp(2*this.tkem.index, this.tkem.size, leaf);
    this.tkem.merge(privateNodes);
  }

  async handleUpdate(update) {
    let pt = await this.tkem.decrypt(update.from, update.ciphertexts);
    this.tkem.merge(update.nodes);
    this.tkem.merge(pt.nodes);
  }
  
  async handleRemove(remove) {
    let pt = await this.tkem.decrypt(remove.index, remove.ciphertexts);
    this.tkem.remove(remove.index);
    this.tkem.merge(pt.root);
    this.tkem.merge(remove.subtreeHeads, true);
  }

  async handleSelfMove(move, leaf) {
    console.log(">>> handleSelfMove");
    let privateNodes = await TreeKEM.hashUp(2 * move.to, this.tkem.size, leaf);
    this.tkem.remove(move.from);
    this.tkem.merge(privateNodes);
    this.tkem.index = move.to;
  }

  async handleMove(move) {
    console.log(">>> handleMove");
    let pt = await this.tkem.decrypt(move.to, move.ciphertexts);
    this.tkem.remove(move.from);
    this.tkem.merge(move.nodes);
    this.tkem.merge(pt.nodes);
  }
}

module.exports = TreeKEMState;
