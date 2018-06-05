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
    let ct = await tkem.encrypt(leaf)
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
    let privateNodes = await TreeKEM.hashUp(2*this.tkem.index, this.tkem.size, leaf);
    this.tkem.merge(privateNodes);
  }

  async handleUpdate(update) {
    let pt = await this.tkem.decrypt(update.from, update.ciphertexts);
    this.tkem.merge(update.nodes);
    this.tkem.merge(pt.nodes);
  }
  
  handleRemove(remove) {/* TODO */}
}

module.exports = TreeKEMState;
