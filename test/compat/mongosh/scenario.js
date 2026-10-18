// mongosh scenario, run with: mongosh --nodb --eval "$(cat scenario.js)"
const assert = (c, m) => { if (!c) throw new Error('assertion failed: ' + (m || '')); };
const eq = (x, y, m) => assert(JSON.stringify(x) === JSON.stringify(y), `${m || ''} got ${JSON.stringify(x)} want ${JSON.stringify(y)}`);
const env = process.env;
const modes = {
  appname: [env.COMPAT_APPNAME_A, env.COMPAT_APPNAME_B],
  static: [env.COMPAT_STATIC_A, env.COMPAT_STATIC_B],
};

for (const [mode, [uriA, uriB]] of Object.entries(modes)) {
  const name = `compat_sh_${mode}`;
  const ca = new Mongo(uriA), cb = new Mongo(uriB);
  const da = ca.getDB(name), db = cb.getDB(name);
  try {
    // CRUD
    da.items.insertMany([{ sku: 'x', qty: 1 }, { sku: 'y', qty: 2 }, { sku: 'z', qty: 3 }]);
    db.items.insertOne({ sku: 'x', qty: 100 });
    eq(da.items.countDocuments({}), 3); eq(db.items.countDocuments({}), 1);
    eq(db.items.findOne({ sku: 'y' }), null);
    eq(da.items.updateMany({}, { $inc: { qty: 10 } }).modifiedCount, 3);
    eq(db.items.findOne({ sku: 'x' }).qty, 100);
    eq(da.items.findOneAndUpdate({ sku: 'x' }, { $set: { qty: 7 } }, { returnDocument: 'after' }).qty, 7);
    eq(da.items.deleteOne({ sku: 'z' }).deletedCount, 1);
    eq(db.items.deleteMany({}).deletedCount, 1);
    eq(da.items.distinct('sku').sort(), ['x', 'y']);

    // bulk
    const r = da.items.bulkWrite([
      { insertOne: { document: { sku: 'b1', qty: 1 } } },
      { updateOne: { filter: { sku: 'b1' }, update: { $set: { qty: 5 } } } },
      { replaceOne: { filter: { sku: 'x' }, replacement: { sku: 'x', qty: 99 } } },
      { deleteOne: { filter: { sku: 'y' } } },
    ]);
    eq([r.insertedCount, r.modifiedCount, r.deletedCount], [1, 2, 1], 'bulk');
    const bb = db.items.initializeUnorderedBulkOp(); bb.insert({ sku: 'bb' }); bb.execute();
    eq(da.items.find().toArray().map(d => d.sku).sort(), ['b1', 'x']);
    eq(db.items.countDocuments({}), 1);

    // $lookup
    for (const [d, t] of [[da, 'A'], [db, 'B']]) {
      d.cust.insertOne({ cid: 1, name: 'cust-' + t });
      d.orders.insertMany([{ cid: 1, o: `o-${t}-1` }, { cid: 1, o: `o-${t}-2` }]);
    }
    const j = da.orders.aggregate([{ $lookup: { from: 'cust', localField: 'cid', foreignField: 'cid', as: 'c' } }]).toArray();
    eq(j.length, 2); j.forEach(x => eq(x.c.map(c => c.name), ['cust-A']));
    const jb = db.orders.aggregate([{ $lookup: { from: 'cust', let: { c: '$cid' }, pipeline: [{ $match: { $expr: { $eq: ['$cid', '$$c'] } } }], as: 'c' } }]).toArray();
    eq(jb.length, 2); jb.forEach(x => eq(x.c.map(c => c.name), ['cust-B']));

    // transactions
    da.createCollection('tx1'); da.createCollection('tx2');
    const s = ca.startSession();
    s.withTransaction(() => {
      s.getDatabase(name).tx1.insertOne({ k: 1 });
      s.getDatabase(name).tx2.insertOne({ k: 2 });
    });
    s.endSession();
    eq(da.tx1.countDocuments({}), 1);
    const s2 = ca.startSession();
    s2.startTransaction();
    s2.getDatabase(name).tx1.insertOne({ k: 'aborted' });
    s2.abortTransaction(); s2.endSession();
    eq(da.tx1.countDocuments({ k: 'aborted' }), 0);
    eq(db.tx1.countDocuments({}), 0);

    // change stream
    if (env.COMPAT_CHANGE_STREAMS !== '1') {
      let code = 0;
      try { da.stream.watch().tryNext(); } catch (e) { code = e.code; }
      assert(code === 115, 'change streams on MongoDB < 6.0 must fail with CommandNotSupported, got ' + code);
    } else {
      const cs = da.stream.watch([], { fullDocument: 'updateLookup' });
      cs.tryNext();
      sleep(500);
      db.stream.insertOne({ who: 'B' });
      da.stream.insertOne({ who: 'A' });
      let ev = null;
      for (let i = 0; i < 60 && !ev; i++) { ev = cs.tryNext(); if (!ev) sleep(250); }
      assert(ev, 'change stream timeout');
      eq([ev.operationType, ev.fullDocument.who], ['insert', 'A']);
      cs.close();

    }

    // indexes
    da.items.createIndex({ sku: 1 }, { unique: true, name: 'sku_u' });
    db.items.createIndex({ sku: 1 }, { unique: true, name: 'sku_u' });
    db.items.insertOne({ sku: 'x' });
    let dup = false;
    try { da.items.insertOne({ sku: 'x' }); } catch (e) { dup = e.code === 11000; }
    assert(dup, 'unique index violated per tenant');
    const idx = da.items.getIndexes();
    assert(idx.some(i => i.name === 'sku_u'), 'index listed');
    assert(idx.every(i => !('tenantId' in i.key)), 'tenantId not in index keys');
    assert(da.getCollectionNames().includes('items'));
    print(`mongosh [${mode}] ok`);
  } finally {
    const up = new Mongo(env.COMPAT_UPSTREAM);
    up.getDB(name).dropDatabase();
    ca.close(); cb.close(); up.close();
  }
}
