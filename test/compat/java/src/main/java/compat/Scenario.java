package compat;

import com.mongodb.MongoWriteException;
import com.mongodb.bulk.BulkWriteResult;
import com.mongodb.client.*;
import com.mongodb.client.model.*;
import com.mongodb.client.result.*;
import org.bson.Document;

import java.util.*;
import java.util.stream.Collectors;

import static com.mongodb.client.model.Filters.*;

/** Java sync driver scenario: CRUD, bulk, $lookup, transactions, change streams, indexes, isolation. */
public class Scenario {
    static void check(boolean c, String m) { if (!c) throw new AssertionError(m); }
    static void same(Object got, Object want, String m) { check(Objects.equals(got, want), m + ": got " + got + " want " + want); }

    public static void main(String[] args) {
        run("appname", System.getenv("COMPAT_APPNAME_A"), System.getenv("COMPAT_APPNAME_B"));
        run("static", System.getenv("COMPAT_STATIC_A"), System.getenv("COMPAT_STATIC_B"));
    }

    static void run(String mode, String uriA, String uriB) {
        String name = "compat_java_" + mode;
        try (MongoClient a = MongoClients.create(uriA); MongoClient b = MongoClients.create(uriB)) {
            MongoDatabase da = a.getDatabase(name), db = b.getDatabase(name);
            try {
                MongoCollection<Document> items = da.getCollection("items"), itemsB = db.getCollection("items");
                items.insertMany(List.of(new Document("sku", "x").append("qty", 1), new Document("sku", "y").append("qty", 2),
                        new Document("sku", "z").append("qty", 3)));
                itemsB.insertOne(new Document("sku", "x").append("qty", 100));
                same(items.countDocuments(), 3L, "countA");
                same(itemsB.countDocuments(), 1L, "countB");
                check(itemsB.find(eq("sku", "y")).first() == null, "B must not see A's y");
                same(items.updateMany(new Document(), Updates.inc("qty", 10)).getModifiedCount(), 3L, "updateMany");
                same(itemsB.find(eq("sku", "x")).first().get("qty"), 100, "B qty untouched");
                Document f = items.findOneAndUpdate(eq("sku", "x"), Updates.set("qty", 7),
                        new FindOneAndUpdateOptions().returnDocument(ReturnDocument.AFTER));
                same(f.get("qty"), 7, "findOneAndUpdate");
                same(items.deleteOne(eq("sku", "z")).getDeletedCount(), 1L, "deleteOne");
                same(itemsB.deleteMany(new Document()).getDeletedCount(), 1L, "deleteMany B");

                BulkWriteResult r = items.bulkWrite(List.of(
                        new InsertOneModel<>(new Document("sku", "b1").append("qty", 1)),
                        new UpdateOneModel<>(eq("sku", "b1"), Updates.set("qty", 5)),
                        new ReplaceOneModel<>(eq("sku", "x"), new Document("sku", "x").append("qty", 99)),
                        new DeleteOneModel<>(eq("sku", "y"))));
                same(r.getInsertedCount(), 1, "bulk inserted");
                same(r.getModifiedCount(), 2, "bulk modified");
                same(r.getDeletedCount(), 1, "bulk deleted");
                itemsB.bulkWrite(List.of(new InsertOneModel<>(new Document("sku", "bb"))), new BulkWriteOptions().ordered(false));
                same(items.find().into(new ArrayList<>()).stream().map(d -> d.getString("sku")).sorted().collect(Collectors.toList()),
                        List.of("b1", "x"), "docs after bulk");
                same(itemsB.countDocuments(), 1L, "B after bulk");

                for (var e : Map.of(da, "A", db, "B").entrySet()) {
                    e.getKey().getCollection("cust").insertOne(new Document("cid", 1).append("name", "cust-" + e.getValue()));
                    e.getKey().getCollection("orders").insertMany(List.of(
                            new Document("cid", 1).append("o", "o-" + e.getValue() + "-1"),
                            new Document("cid", 1).append("o", "o-" + e.getValue() + "-2")));
                }
                List<Document> j = da.getCollection("orders").aggregate(List.of(
                        Aggregates.lookup("cust", "cid", "cid", "c"))).into(new ArrayList<>());
                same(j.size(), 2, "lookup size");
                for (Document d : j) {
                    List<Document> c = d.getList("c", Document.class);
                    same(c.size(), 1, "lookup joined");
                    same(c.get(0).getString("name"), "cust-A", "lookup tenant");
                }

                da.createCollection("tx1");
                da.createCollection("tx2");
                try (ClientSession s = a.startSession()) {
                    s.withTransaction(() -> {
                        da.getCollection("tx1").insertOne(s, new Document("k", 1));
                        da.getCollection("tx2").insertOne(s, new Document("k", 2));
                        return null;
                    });
                }
                same(da.getCollection("tx1").countDocuments(), 1L, "tx commit");
                try (ClientSession s = a.startSession()) {
                    s.startTransaction();
                    da.getCollection("tx1").insertOne(s, new Document("k", "aborted"));
                    s.abortTransaction();
                }
                same(da.getCollection("tx1").countDocuments(eq("k", "aborted")), 0L, "tx abort");
                same(db.getCollection("tx1").countDocuments(), 0L, "tx isolation");

                if (!"1".equals(System.getenv("COMPAT_CHANGE_STREAMS"))) {
                    try {
                        da.getCollection("stream").watch().cursor().tryNext();
                        check(false, "change streams on MongoDB < 6.0 must fail");
                    } catch (com.mongodb.MongoCommandException e) {
                        same(e.getErrorCode(), 115, "CommandNotSupported");
                    }
                } else {
                try (MongoChangeStreamCursor<com.mongodb.client.model.changestream.ChangeStreamDocument<Document>> cs =
                             da.getCollection("stream").watch().fullDocument(com.mongodb.client.model.changestream.FullDocument.UPDATE_LOOKUP).cursor()) {
                    cs.tryNext();
                    Thread.sleep(500);
                    db.getCollection("stream").insertOne(new Document("who", "B"));
                    da.getCollection("stream").insertOne(new Document("who", "A"));
                    var ev = (com.mongodb.client.model.changestream.ChangeStreamDocument<Document>) null;
                    for (int i = 0; i < 60 && ev == null; i++) { ev = cs.tryNext(); if (ev == null) Thread.sleep(250); }
                    check(ev != null, "change stream timeout");
                    same(ev.getFullDocument().getString("who"), "A", "change stream tenant");
                }

                }

                items.createIndex(Indexes.ascending("sku"), new IndexOptions().unique(true).name("sku_u"));
                itemsB.createIndex(Indexes.ascending("sku"), new IndexOptions().unique(true).name("sku_u"));
                itemsB.insertOne(new Document("sku", "x"));
                try {
                    items.insertOne(new Document("sku", "x"));
                    check(false, "duplicate should fail");
                } catch (MongoWriteException e) {
                    same(e.getError().getCode(), 11000, "dup code");
                }
                List<Document> idx = items.listIndexes().into(new ArrayList<>());
                check(idx.stream().anyMatch(i -> "sku_u".equals(i.getString("name"))), "index listed");
                check(idx.stream().noneMatch(i -> ((Document) i.get("key")).containsKey("tenantId")), "tenantId leaked into index key");
                System.out.println("java driver [" + mode + "] ok");
            } catch (InterruptedException e) {
                throw new RuntimeException(e);
            } finally {
                try (MongoClient up = MongoClients.create(System.getenv("COMPAT_UPSTREAM"))) { up.getDatabase(name).drop(); }
            }
        }
    }
}
