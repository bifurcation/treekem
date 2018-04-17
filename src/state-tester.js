'use strict';

const iota = require('./iota');

async function testUserAdd(State) {
  const testGroupSize = 5;

  let creator = await State.oneMemberGroup(new Uint8Array([0]));
  let members = [creator];

  for (let i = 1; i < testGroupSize; ++i) {
    let leaf = window.crypto.getRandomValues(new Uint8Array(32));
    let gik = members[members.length - 1].groupInitKey;
    let ua = await State.join(leaf, gik);

    let joiner = await State.fromUserAdd(leaf, ua, gik);
    
    for (let m of members) {
      await m.handleUserAdd(ua);

      let eq = await joiner.equal(m);
      if (!eq) {
        throw 'state-user-add';
      }
    }

    members.push(joiner);
  }

  console.log("[state-user-add] PASS");
}

async function testGroupAdd(State) {
  const testGroupSize = 5;

  let creator = await State.oneMemberGroup(new Uint8Array([0]));
  let members = [creator];

  for (let i = 1; i < testGroupSize; ++i) {
    let initKP = await iota(window.crypto.getRandomValues(new Uint8Array(4)))
    let ga = await members[members.length - 1].add(initKP.publicKey)

    let joiner = await State.fromGroupAdd(initKP.privateKey, ga);

    for (let m of members) {
      await m.handleGroupAdd(ga);

      let eq = await joiner.equal(m);
      if (!eq) {
        throw 'state-group-add';
      }
    }

    members.push(joiner);
  }

  console.log("state-group-add] PASS");
}

async function testUpdate(State) {
  // Create a group via GroupAdds
  const testGroupSize = 5;
  let creator = await State.oneMemberGroup(new Uint8Array([0]));
  let members = [creator];
  for (let i = 1; i < testGroupSize; ++i) {
    let initKP = await iota(window.crypto.getRandomValues(new Uint8Array(4)))
    let ga = await members[members.length - 1].add(initKP.publicKey)

    for (let m of members) {
      await m.handleGroupAdd(ga);
    }

    let joiner = await State.fromGroupAdd(initKP.privateKey, ga);
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

      let eq = await m1.equal(m2);
      if (!eq) {
        throw 'state-update';
      }
    }
  }
  
  console.log("[state-update] PASS");
}

module.exports = {
  test: async function(State) {
    await testUserAdd(State);
    await testGroupAdd(State);
    await testUpdate(State);
  },
};
