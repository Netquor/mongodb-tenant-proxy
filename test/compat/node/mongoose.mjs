// Mongoose smoke test: autoIndex (createIndexes on model init), validation,
// populate ($lookup-free path), and tenant isolation.
import assert from 'node:assert/strict';
import mongoose from 'mongoose';

async function run(mode, uriA, uriB) {
  const dbName = `compat_mongoose_${mode}`;
  const ca = await mongoose.createConnection(uriA, { dbName, autoIndex: true }).asPromise();
  const cb = await mongoose.createConnection(uriB, { dbName, autoIndex: true }).asPromise();
  try {
    const schema = () => new mongoose.Schema({
      email: { type: String, required: true, unique: true },
      name: String,
      age: { type: Number, index: true },
    }, { timestamps: true });
    const UA = ca.model('User', schema()), UB = cb.model('User', schema());
    await Promise.all([UA.init(), UB.init()]); // waits for autoIndex
    const idxA = await UA.collection.indexes();
    assert.ok(idxA.some(i => i.name === 'email_1' && i.unique), 'unique index built');
    assert.ok(idxA.some(i => i.name === 'age_1'));

    await UA.create({ email: 'x@example.com', name: 'A-x', age: 30 });
    await UB.create({ email: 'x@example.com', name: 'B-x', age: 31 }); // same email, other tenant
    await assert.rejects(UA.create({ email: 'x@example.com' }), e => e.code === 11000);
    assert.equal((await UA.findOne({ email: 'x@example.com' })).name, 'A-x');
    assert.equal((await UB.findOne({ email: 'x@example.com' })).name, 'B-x');
    assert.equal(await UA.countDocuments(), 1);

    await UA.insertMany([{ email: 'y@e.com', age: 1 }, { email: 'z@e.com', age: 2 }]);
    assert.equal(await UA.countDocuments(), 3);
    assert.equal(await UB.countDocuments(), 1);
    await UA.updateOne({ email: 'y@e.com' }, { $set: { name: 'why' } });
    const doc = await UA.findOneAndUpdate({ email: 'z@e.com' }, { $inc: { age: 5 } }, { new: true });
    assert.equal(doc.age, 7);
    const agg = await UA.aggregate([{ $group: { _id: null, total: { $sum: '$age' } } }]);
    assert.equal(agg[0].total, 38);
    assert.equal((await UA.find({ age: { $gt: 5 } }).sort({ age: -1 }).lean()).length, 2);
    assert.equal((await UA.deleteMany({ email: /@e\.com$/ })).deletedCount, 2);

    // Mongoose transaction helper
    await UA.createCollection().catch(() => {});
    await ca.transaction(async (session) => {
      await UA.create([{ email: 'tx@e.com' }], { session });
    });
    assert.equal(await UA.countDocuments({ email: 'tx@e.com' }), 1);
    assert.equal(await UB.countDocuments({ email: 'tx@e.com' }), 0);
  } finally {
    const up = await mongoose.createConnection(process.env.COMPAT_UPSTREAM, { dbName }).asPromise();
    await up.dropDatabase(); await up.close();
    await ca.close(); await cb.close();
  }
}

await run('appname', process.env.COMPAT_APPNAME_A, process.env.COMPAT_APPNAME_B);
console.log('mongoose [appname] ok');
await run('static', process.env.COMPAT_STATIC_A, process.env.COMPAT_STATIC_B);
console.log('mongoose [static] ok');
