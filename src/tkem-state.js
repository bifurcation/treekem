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

async function testUserAdd() {
  const testGroupSize = 5;

  let creator = await TKEMState.oneMemberGroup(new Uint8Array([0]));
  let members = [creator];

  for (let i = 1; i < testGroupSize; ++i) {
    let leaf = window.crypto.getRandomValues(new Uint8Array(32));
    let gik = members[members.length - 1].groupInitKey;
    let ua = await TKEMState.join(leaf, gik);

    let joiner = await TKEMState.fromUserAdd(leaf, ua, gik);
    
    for (let m of members) {
      await m.handleUserAdd(ua);

      let eq = await joiner.tkem.equal(m.tkem);
      if (!eq) {
        throw 'tkem-user-add';
      }
    }

    members.push(joiner);
  }

  console.log("[tkem-user-add] PASS");
}

async function testGroupAdd() {
  const testGroupSize = 5;

  let creator = await TKEMState.oneMemberGroup(new Uint8Array([0]));
  let members = [creator];

  for (let i = 1; i < testGroupSize; ++i) {
    let initKP = await iota(window.crypto.getRandomValues(new Uint8Array(4)))
    let ga = await members[members.length - 1].add(initKP.publicKey)

    let joiner = await TKEMState.fromGroupAdd(initKP.privateKey, ga);

    for (let m of members) {
      await m.handleGroupAdd(ga);

      let eq = await joiner.tkem.equal(m.tkem);
      if (!eq) {
        throw 'tkem-group-add';
      }
    }

    members.push(joiner);
  }

  console.log("[tkem-group-add] PASS");
}

async function testUpdate() {
  // Create a group via GroupAdds
  const testGroupSize = 5;
  let creator = await TKEMState.oneMemberGroup(new Uint8Array([0]));
  let members = [creator];
  for (let i = 1; i < testGroupSize; ++i) {
    let initKP = await iota(window.crypto.getRandomValues(new Uint8Array(4)))
    let ga = await members[members.length - 1].add(initKP.publicKey)

    for (let m of members) {
      await m.handleGroupAdd(ga);
    }

    let joiner = await TKEMState.fromGroupAdd(initKP.privateKey, ga);
    members.push(joiner);
  }

  // Have each member update and verify that others are consistent
  for (let m1 of members) {
    let leaf = crypto.getRandomValues(new Uint8Array(32));
    let update = await m1.update(leaf);

    await m1.handleSelfUpdate(update, leaf);

    for (let m2 of members) {
      if (m2.index == m1.index) {
        continue
      }
        
      await m2.handleUpdate(update);

      let eq = await m1.tkem.equal(m2.tkem);
      if (!eq) {
        throw 'tkem-update';
      }
    }
  }
  
  console.log("[tkem-update] PASS");
}

async function test() {
  await testUserAdd();
  await testGroupAdd();
  await testUpdate();
}

module.exports = {
  class: TKEMState,
  test: test,
};
