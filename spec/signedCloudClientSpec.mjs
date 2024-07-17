import Security from '@ki1r0y/distributed-security';
import {Collection} from '../index.mjs';

// TODO:
// - implement mutable and immutable collections, but does it make sense to be subclasses in which a specialization happens twice? Might be ok with Security being pluggable?
// - Tests should cover each of the eight combinations of Storage, Security, mutability.
// - fixmes inline below
// - Should immutable really use owner? Isn't there no advantage in terms of not forking?
// - Does signed-cloud-server behave correctly for subsequent writes:
//   - of an immutable must leave existing author intact
//   - of a mutable must confirm that new owner matches old.
// - Can any of the asynchronous steps be done in parallel? E.g., hashing?
// - Can Secrurity.Storage use this (so that paths are consistent)?
// - Cloud server needs to clean up directories
// - Should this instantiate the type, or just return a spec as now? Maybe the conversion both ways between object and specification should be outside of this?

// The structure of these test is meant to illustrate the following:
// - How to store and retrieve data
// - How to customize how this is done
// - How various choices effect performance.


const MemoryStorage = {
  collections: {},
  async store(collectionTag, tag, signature) {
    const collection = this.collections[collectionTag] ||= {};
    collection[tag] = signature;
    return null; // Must not return undefined.
  },
  async retrieve(collectionTag, tag) {
    return this.collections[collectionTag][tag];
  }
};
const NoSecurity = {
  async package(identity, claims) {
    return JSON.stringify({identity, claims});
  },
  unpackage(packaged, options) {
    return JSON.parse(packaged);
  }
};
const NoSecurityImmutable = {
  async package(security, identity, {owner, author, ...options}) {
    const cleanOptions = owner===author ? {owner, ...options} : {author, owner, ...options},
          packaged = security.package(identity, cleanOptions),
          hash = await Security.hashText(JSON.stringify(identity));
    return [packaged, Security.encodeBase64url(hash)];
  },
  unpackage(security, packaged, options) {
    const {identity, claims} = security.unpackage(packaged, options),
          {owner, author, time} = claims;
    return {...identity, ...(author ? {author} : {}), owner, timestamp: time};
  }
}


class Basic extends Collection(Object) {
  Storage = MemoryStorage;
  Security = NoSecurity;
  Identity = NoSecurityImmutable;
}

class Signed extends Collection(Object) {
  Storage = MemoryStorage;
}

function delay(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

describe('Signed Cloud Client', function () {
  let device, me, team,
      persistables = {},
      copies = {},
      time = Date.now(),
      hash,
      a = [1, "foo"],
      b = {x: 2, y: 3},
      c = 4,
      d = "bar",
      baseData = {c, d, b, a}, // Note: not alphabetical.
      canonicalized = {a, b, c, d};
  beforeAll(async function () {
    device = await Security.create(),
    me = await Security.create(device);
    team = await Security.create(me);
    await Security.sign("exercise before timing tests", team); // Creating a tag doesn't cache it, which is expensive. (Might be creating a bunch.)
    hash = Security.encodeBase64url(await Security.hashText(JSON.stringify(canonicalized)));

    persistables.authorOwned = {owner: me, ...baseData};
    persistables.teamOwned = {owner: team, author: me, ...baseData};

    copies.authorOwned = {...canonicalized, owner: me, timestamp: time};
    copies.teamOwned = {...canonicalized, author: me, owner: team, timestamp: time};
  }, 15e3);
  afterAll(async function () {
    await Security.destroy(team);
    await Security.destroy(me);
    await Security.destroy(device);
  });
  function test1(label, collectionType, tag, storeTime, retrieveTime) {
    describe(label, function () {
      const collection = new collectionType(label);
      it('stores and retrieves.', async function () {
        // The server tests ensure that one cannot re-save an immutable with different author/owner attribution.
        // Here we just avoid that issue by passing different collections with different names to our test suites,
        // so that the authorOwned and teamOwned data are saved to different collection names.
        const persistable = {...persistables[label]}, // A copy we can bash
              expected = copies[label],
              promise = collection.store(persistable, {time});
        persistable.c = 27; // alter the persistable before it is stored.
        const tag = await promise,
              copy = await collection.retrieve(tag);
        expect(copy).toEqual(expected);
        expect(tag).toBe(hash);
      });
      it('speed.', async function () {
        const base = persistables[label],
              items = Array.from({length: 1000}, index => ({index, ...base})),

              gc1 = await delay(2e3),
              startStoring = Date.now(),
              tags = await Promise.all(items.map(item => collection.store(item))),
              stored = Date.now(),

              gc2 = await delay(2e3),
              startRetrieving = Date.now(),
              retrieves = await Promise.all(tags.map(tag => collection.retrieve(tag))),
              retrieved = Date.now(),

              storeElapsed = stored - startStoring,
              retrieveElapsed = retrieved - startRetrieving,
              storesPerSecond = 1e6 / storeElapsed,
              retrievesPerSecond = 1e6 / retrieveElapsed;
        console.log(`${collection.constructor.name}-${label} ${storesPerSecond.toFixed(0)}/${retrievesPerSecond.toFixed(0)} stores/retrieves per second`);
        expect(storesPerSecond).toBeGreaterThan(storeTime);
        expect(retrievesPerSecond).toBeGreaterThan(retrieveTime);
      }, 30e3);
    });
  }
  describe('in-memory, no-crypto,', function () {
    describe('immutable,', function () {
      test1('authorOwned', Basic, hash,  24e3, 90e3);
      test1('teamOwned', Basic, hash,    24e3, 90e3);
    });
  });
  describe('in-memory, signed,', function () {
    describe('immutable', function () {
      test1('authorOwned', Signed, hash, 1.8e3,  1.8e3);
      test1('teamOwned', Signed, hash,   0.9e3,  0.9e3);
    });
  });
});
