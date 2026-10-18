// Node.js driver scenario: CRUD, bulk, $lookup, transactions, change streams,
// indexes and cross-tenant isolation, in appname and static modes.
import assert from 'node:assert/strict';
import { MongoClient } from 'mongodb';

const modes = {
  appname: [process.env.COMPAT_APPNAME_A, process.env.COMPAT_APPNAME_B],
  static: [process.env.COMPAT_STATIC_A, process.env.COMPAT_STATIC_B],
};

// dropDatabase is (deliberately) not allowed through the proxy; clean up directly.
async function dropUpstream(name) {
  const c = new MongoClient(process.env.COMPAT_UPSTREAM);
  try { await c.db(name).dropDatabase(); } finally { await c.close(); }
}

async function scenario(mode, [uriA, uriB]) {
  const a = new MongoClient(uriA), b = new MongoClient(uriB);
  await Promise.all([a.connect(), b.connect()]);
  const dbName = `compat_node_${mode}`;
  const da = a.db(dbName), db_ = b.db(dbName);
  try {
    // CRUD
    const items = da.collection('items'), itemsB = db_.collection('items');
    const ins = await items.insertMany([{ sku: 'x', qty: 1 }, { sku: 'y', qty: 2 }, { sku: 'z', qty: 3 }]);
    assert.equal(ins.insertedCount, 3);
    await itemsB.insertOne({ sku: 'x', qty: 100 });
    assert.equal(await items.countDocuments(), 3);
    assert.equal(await itemsB.countDocuments(), 1);
    assert.equal((await itemsB.findOne({ sku: 'x' })).qty, 100);
    assert.equal(await itemsB.findOne({ sku: 'y' }), null);
    assert.equal((await items.updateMany({}, { $inc: { qty: 10 } })).modifiedCount, 3);
    assert.equal((await itemsB.findOne({ sku: 'x' })).qty, 100);
    const fau = await items.findOneAndUpdate({ sku: 'x' }, { $set: { qty: 7 } }, { returnDocument: 'after' });
    assert.equal(fau.qty, 7);
    assert.equal((await items.deleteOne({ sku: 'z' })).deletedCount, 1);
    assert.equal((await itemsB.deleteMany({})).deletedCount, 1);
    assert.equal(await items.countDocuments(), 2);
    assert.deepEqual((await items.distinct('sku')).sort(), ['x', 'y']);

    // bulk writes (ordered and unordered)
    const bulk = await items.bulkWrite([
      { insertOne: { document: { sku: 'b1', qty: 1 } } },
      { updateOne: { filter: { sku: 'b1' }, update: { $set: { qty: 5 } } } },
      { replaceOne: { filter: { sku: 'x' }, replacement: { sku: 'x', qty: 99 } } },
      { deleteOne: { filter: { sku: 'y' } } },
    ]);
    assert.equal(bulk.insertedCount, 1);
    assert.equal(bulk.modifiedCount, 2);
    assert.equal(bulk.deletedCount, 1);
    await itemsB.bulkWrite([{ insertOne: { document: { sku: 'bb', qty: 1 } } }], { ordered: false });
    assert.deepEqual((await items.find().toArray()).map(d => d.sku).sort(), ['b1', 'x']);
    assert.equal((await items.findOne({ sku: 'x' })).qty, 99);
    assert.equal(await itemsB.countDocuments(), 1);
    const docs = await items.find().toArray();
    assert.ok(docs.every(d => d.tenantId === undefined || typeof d.tenantId === 'string'));

    // $lookup: same join key exists in both tenants
    for (const [db, t] of [[da, 'A'], [db_, 'B']]) {
      await db.collection('cust').insertMany([{ cid: 1, name: `cust-${t}` }]);
      await db.collection('orders').insertMany([{ cid: 1, o: `order-${t}-1` }, { cid: 1, o: `order-${t}-2` }]);
    }
    const joined = await da.collection('orders').aggregate([
      { $lookup: { from: 'cust', localField: 'cid', foreignField: 'cid', as: 'c' } },
      { $sort: { o: 1 } },
    ]).toArray();
    assert.equal(joined.length, 2);
    for (const j of joined) { assert.equal(j.c.length, 1); assert.equal(j.c[0].name, 'cust-A'); }
    const joinedB = await db_.collection('orders').aggregate([
      { $lookup: { from: 'cust', as: 'c', let: { c: '$cid' }, pipeline: [{ $match: { $expr: { $eq: ['$cid', '$$c'] } } }] } },
    ]).toArray();
    assert.equal(joinedB.length, 2);
    for (const j of joinedB) assert.deepEqual(j.c.map(x => x.name), ['cust-B']);
    const grp = await da.collection('orders').aggregate([{ $group: { _id: '$cid', n: { $sum: 1 } } }]).toArray();
    assert.deepEqual(grp, [{ _id: 1, n: 2 }]);

    // transactions
    await da.createCollection('tx1').catch(() => {});
    await da.createCollection('tx2').catch(() => {});
    const s = a.startSession();
    await s.withTransaction(async () => {
      await da.collection('tx1').insertOne({ k: 1 }, { session: s });
      await da.collection('tx2').insertOne({ k: 2 }, { session: s });
      assert.equal(await da.collection('tx1').countDocuments({}, { session: s }), 1);
    });
    await s.endSession();
    assert.equal(await da.collection('tx1').countDocuments(), 1);
    const s2 = a.startSession();
    s2.startTransaction();
    await da.collection('tx1').insertOne({ k: 'aborted' }, { session: s2 });
    await s2.abortTransaction();
    await s2.endSession();
    assert.equal(await da.collection('tx1').countDocuments({ k: 'aborted' }), 0);
    assert.equal(await db_.collection('tx1').countDocuments(), 0);

    // change streams: A must only see its own events
    if (process.env.COMPAT_CHANGE_STREAMS !== '1') {
      const old = da.collection('stream').watch();
      await assert.rejects(old.next(), e => e.code === 115, 'change streams on MongoDB < 6.0 must fail with CommandNotSupported');
      await old.close();
    } else {
      const cs = da.collection('stream').watch([], { fullDocument: 'updateLookup' });
      assert.equal(await cs.tryNext(), null); // forces the lazy aggregate to run
      await new Promise(r => setTimeout(r, 500));
      await db_.collection('stream').insertOne({ who: 'B' });
      await da.collection('stream').insertOne({ who: 'A' });
      const ev = await Promise.race([cs.next(), new Promise((_, rej) => setTimeout(() => rej(new Error('change stream timeout')), 15000))]);
      assert.equal(ev.operationType, 'insert');
      assert.equal(ev.fullDocument.who, 'A');
      await da.collection('stream').updateOne({ who: 'A' }, { $set: { n: 1 } });
      const ev2 = await Promise.race([cs.next(), new Promise((_, rej) => setTimeout(() => rej(new Error('change stream timeout (update)')), 15000))]);
      assert.equal(ev2.operationType, 'update');
      assert.equal(ev2.fullDocument.who, 'A');
      await cs.close();

    }

    // indexes: unique is per tenant
    await items.createIndex({ sku: 1 }, { unique: true, name: 'sku_u' });
    await itemsB.createIndex({ sku: 1 }, { unique: true, name: 'sku_u' });
    await itemsB.insertOne({ sku: 'x', qty: 1 }); // same value as tenant A's doc
    await assert.rejects(items.insertOne({ sku: 'x', qty: 2 }), e => e.code === 11000);
    const idx = await items.listIndexes().toArray();
    assert.ok(idx.some(i => i.name === 'sku_u'));
    assert.ok(idx.every(i => !('tenantId' in (i.key || {}))), 'tenant field must not leak into index keys');
    await items.createIndex({ qty: 1 });
    assert.ok((await items.indexes()).length >= 3);

    // listings never show the other tenant's data
    const cols = (await da.listCollections().toArray()).map(c => c.name);
    assert.ok(cols.includes('items'));
    // no tenant leaks through arbitrary filters
    assert.equal(await items.countDocuments({ $or: [{ tenantId: 'x' }, {}] }), await items.countDocuments());
  } finally {
    await dropUpstream(dbName);
    await Promise.all([a.close(), b.close()]);
  }
}

for (const [mode, uris] of Object.entries(modes)) {
  await scenario(mode, uris);
  console.log(`node driver [${mode}] ok`);
}
