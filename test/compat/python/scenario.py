"""PyMongo scenario: CRUD, bulk, $lookup, transactions, change streams, indexes, isolation."""
import os
import time

import pymongo
from pymongo import MongoClient, InsertOne, UpdateOne, ReplaceOne, DeleteOne
from pymongo.errors import DuplicateKeyError

MODES = {
    "appname": (os.environ["COMPAT_APPNAME_A"], os.environ["COMPAT_APPNAME_B"]),
    "static": (os.environ["COMPAT_STATIC_A"], os.environ["COMPAT_STATIC_B"]),
}


def scenario(mode, uri_a, uri_b):
    a, b = MongoClient(uri_a), MongoClient(uri_b)
    name = f"compat_py_{mode}"
    da, db = a[name], b[name]
    try:
        items, items_b = da.items, db.items
        assert len(items.insert_many([{"sku": "x", "qty": 1}, {"sku": "y", "qty": 2}, {"sku": "z", "qty": 3}]).inserted_ids) == 3
        items_b.insert_one({"sku": "x", "qty": 100})
        assert items.count_documents({}) == 3 and items_b.count_documents({}) == 1
        assert items_b.find_one({"sku": "y"}) is None
        assert items.estimated_document_count() >= 0
        assert items.update_many({}, {"$inc": {"qty": 10}}).modified_count == 3
        assert items_b.find_one({"sku": "x"})["qty"] == 100
        d = items.find_one_and_update({"sku": "x"}, {"$set": {"qty": 7}}, return_document=pymongo.ReturnDocument.AFTER)
        assert d["qty"] == 7
        assert items.delete_one({"sku": "z"}).deleted_count == 1
        assert items_b.delete_many({}).deleted_count == 1
        assert sorted(items.distinct("sku")) == ["x", "y"]

        r = items.bulk_write([
            InsertOne({"sku": "b1", "qty": 1}),
            UpdateOne({"sku": "b1"}, {"$set": {"qty": 5}}),
            ReplaceOne({"sku": "x"}, {"sku": "x", "qty": 99}),
            DeleteOne({"sku": "y"}),
        ])
        assert (r.inserted_count, r.modified_count, r.deleted_count) == (1, 2, 1), r.bulk_api_result
        items_b.bulk_write([InsertOne({"sku": "bb"})], ordered=False)
        assert sorted(x["sku"] for x in items.find()) == ["b1", "x"]
        assert items_b.count_documents({}) == 1

        for dbx, t in ((da, "A"), (db, "B")):
            dbx.cust.insert_one({"cid": 1, "name": f"cust-{t}"})
            dbx.orders.insert_many([{"cid": 1, "o": f"o-{t}-1"}, {"cid": 1, "o": f"o-{t}-2"}])
        j = list(da.orders.aggregate([{"$lookup": {"from": "cust", "localField": "cid", "foreignField": "cid", "as": "c"}}]))
        assert len(j) == 2 and all([c["name"] for c in x["c"]] == ["cust-A"] for x in j), j
        jb = list(db.orders.aggregate([{"$lookup": {"from": "cust", "let": {"c": "$cid"}, "pipeline": [{"$match": {"$expr": {"$eq": ["$cid", "$$c"]}}}], "as": "c"}}]))
        assert len(jb) == 2 and all([c["name"] for c in x["c"]] == ["cust-B"] for x in jb), jb

        # transactions
        da.create_collection("tx1")
        da.create_collection("tx2")
        with a.start_session() as s:
            def body(sess):
                da.tx1.insert_one({"k": 1}, session=sess)
                da.tx2.insert_one({"k": 2}, session=sess)
            s.with_transaction(body)
        assert da.tx1.count_documents({}) == 1
        with a.start_session() as s:
            s.start_transaction()
            da.tx1.insert_one({"k": "aborted"}, session=s)
            s.abort_transaction()
        assert da.tx1.count_documents({"k": "aborted"}) == 0
        assert db.tx1.count_documents({}) == 0

        # change streams
        if os.environ.get("COMPAT_CHANGE_STREAMS") != "1":
            try:
                with da.stream.watch() as cs:
                    cs.try_next()
                raise AssertionError("change stream should fail on MongoDB < 6.0")
            except pymongo.errors.OperationFailure as e:
                assert e.code == 115, e
        else:
            with da.stream.watch(full_document="updateLookup") as cs:
                assert cs.try_next() is None
                db.stream.insert_one({"who": "B"})
                da.stream.insert_one({"who": "A"})
                ev = None
                deadline = time.time() + 15
                while ev is None and time.time() < deadline:
                    ev = cs.try_next()
                assert ev is not None, "change stream timeout"
                assert ev["operationType"] == "insert" and ev["fullDocument"]["who"] == "A", ev
                da.stream.update_one({"who": "A"}, {"$set": {"n": 1}})
                ev = None
                deadline = time.time() + 15
                while ev is None and time.time() < deadline:
                    ev = cs.try_next()
                assert ev is not None and ev["operationType"] == "update" and ev["fullDocument"]["who"] == "A", ev

        # indexes
        items.create_index([("sku", 1)], unique=True, name="sku_u")
        items_b.create_index([("sku", 1)], unique=True, name="sku_u")
        items_b.insert_one({"sku": "x"})
        try:
            items.insert_one({"sku": "x"})
            raise AssertionError("duplicate should have failed")
        except DuplicateKeyError:
            pass
        names = [i["name"] for i in items.list_indexes()]
        assert "sku_u" in names, names
        assert all("tenantId" not in i["key"] for i in items.list_indexes())
        assert "items" in da.list_collection_names()
    finally:
        with MongoClient(os.environ["COMPAT_UPSTREAM"]) as up:  # dropDatabase is blocked through the proxy
            up.drop_database(name)
        a.close()
        b.close()


for mode, (ua, ub) in MODES.items():
    scenario(mode, ua, ub)
    print(f"pymongo {pymongo.version} [{mode}] ok")
