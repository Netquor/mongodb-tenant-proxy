// Handshake / wire-level options real applications set.
import assert from 'node:assert/strict';
import { MongoClient, ServerApiVersion } from 'mongodb';

const uriA = process.env.COMPAT_APPNAME_A;
const sep = u => u + (u.includes('?') ? '&' : '?');
const cases = {
  'serverApi v1 (non-strict)': [uriA, { serverApi: { version: ServerApiVersion.v1 } }],
  'serverApi v1 strict': [uriA, { serverApi: { version: ServerApiVersion.v1, strict: true } }],
  'zlib compression': [sep(uriA) + 'compressors=zlib', {}],
  'zstd compression': [sep(uriA) + 'compressors=zstd', {}],
  'snappy compression': [sep(uriA) + 'compressors=snappy', {}],
  'retryWrites=false, w=majority, readConcern majority': [sep(uriA) + 'retryWrites=false&w=majority&readConcernLevel=majority', {}],
  'directConnection': [sep(uriA) + 'directConnection=true', {}],
};
let failed = 0;
for (const [name, [uri, opts]] of Object.entries(cases)) {
  const c = new MongoClient(uri, { serverSelectionTimeoutMS: 8000, ...opts });
  try {
    const coll = c.db('compat_extras').collection('big');
    await coll.deleteMany({});
    await coll.insertMany(Array.from({ length: 1500 }, (_, i) => ({ i, pad: 'x'.repeat(200) })));
    const seen = await coll.find({}, { batchSize: 100 }).sort({ i: 1 }).toArray(); // multiple getMores
    assert.equal(seen.length, 1500);
    assert.equal((await coll.find().sort({ i: -1 }).skip(10).limit(5).toArray())[0].i, 1489);
    assert.equal((await coll.find({ i: { $gt: 1 } }).collation({ locale: 'en' }).hint({ _id: 1 }).toArray()).length, 1498);
    assert.equal(await coll.countDocuments({ i: { $lt: 10 } }), 10);
    await coll.deleteMany({});
    console.log(`ok   ${name}`);
  } catch (e) {
    failed++;
    console.log(`FAIL ${name}: ${e.message}`);
  } finally {
    await c.close();
  }
}
const up = new MongoClient(process.env.COMPAT_UPSTREAM);
await up.db('compat_extras').dropDatabase(); await up.close();
process.exit(failed ? 1 : 0);
