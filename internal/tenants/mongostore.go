package tenants

import (
	"context"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// MongoStore keeps dynamic tenants and users in a control database on MongoDB,
// in collections <prefix>_tenants and <prefix>_users. Several proxy replicas can
// share it; each polls via Registry.Run.
type MongoStore struct {
	cli     *mongo.Client
	tenants *mongo.Collection
	users   *mongo.Collection
}

type tenantDoc struct {
	ID        string    `bson:"_id"`
	Disabled  bool      `bson:"disabled"`
	MaxConns  int       `bson:"maxConns"`
	CreatedAt time.Time `bson:"createdAt"`
}

type userDoc struct {
	Username   string    `bson:"_id"`
	TenantID   string    `bson:"tenantId"`
	Salt       string    `bson:"salt"`
	Iterations int       `bson:"iterations"`
	StoredKey  string    `bson:"storedKey"`
	ServerKey  string    `bson:"serverKey"`
	CreatedAt  time.Time `bson:"createdAt"`
}

// NewMongoStore connects to uri and uses database/prefix for storage.
func NewMongoStore(ctx context.Context, uri, database, prefix string) (*MongoStore, error) {
	if database == "" {
		database = "mtp_control"
	}
	if prefix == "" {
		prefix = "mtp"
	}
	cli, err := mongo.Connect(options.Client().ApplyURI(uri).SetServerSelectionTimeout(10 * time.Second))
	if err != nil {
		return nil, err
	}
	pctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if err := cli.Ping(pctx, nil); err != nil {
		cli.Disconnect(context.Background())
		return nil, fmt.Errorf("control store: %w", err)
	}
	db := cli.Database(database)
	return &MongoStore{cli: cli, tenants: db.Collection(prefix + "_tenants"), users: db.Collection(prefix + "_users")}, nil
}

func (m *MongoStore) List(ctx context.Context) ([]Tenant, []User, error) {
	var ts []Tenant
	cur, err := m.tenants.Find(ctx, bson.D{})
	if err != nil {
		return nil, nil, err
	}
	var tds []tenantDoc
	if err := cur.All(ctx, &tds); err != nil {
		return nil, nil, err
	}
	for _, d := range tds {
		ts = append(ts, Tenant{ID: d.ID, Disabled: d.Disabled, MaxConns: d.MaxConns, CreatedAt: d.CreatedAt})
	}
	cur, err = m.users.Find(ctx, bson.D{})
	if err != nil {
		return nil, nil, err
	}
	var uds []userDoc
	if err := cur.All(ctx, &uds); err != nil {
		return nil, nil, err
	}
	var us []User
	for _, d := range uds {
		u := User{CreatedAt: d.CreatedAt}
		u.Username, u.TenantID, u.Salt, u.Iterations, u.StoredKey, u.ServerKey = d.Username, d.TenantID, d.Salt, d.Iterations, d.StoredKey, d.ServerKey
		us = append(us, u)
	}
	return ts, us, nil
}

func (m *MongoStore) PutTenant(ctx context.Context, t Tenant) error {
	_, err := m.tenants.ReplaceOne(ctx, bson.D{{Key: "_id", Value: t.ID}},
		tenantDoc{ID: t.ID, Disabled: t.Disabled, MaxConns: t.MaxConns, CreatedAt: t.CreatedAt},
		options.Replace().SetUpsert(true))
	return err
}

func (m *MongoStore) DeleteTenant(ctx context.Context, id string) error {
	if _, err := m.users.DeleteMany(ctx, bson.D{{Key: "tenantId", Value: id}}); err != nil {
		return err
	}
	_, err := m.tenants.DeleteOne(ctx, bson.D{{Key: "_id", Value: id}})
	return err
}

func (m *MongoStore) PutUser(ctx context.Context, u User) error {
	_, err := m.users.ReplaceOne(ctx, bson.D{{Key: "_id", Value: u.Username}},
		userDoc{Username: u.Username, TenantID: u.TenantID, Salt: u.Salt, Iterations: u.Iterations,
			StoredKey: u.StoredKey, ServerKey: u.ServerKey, CreatedAt: u.CreatedAt},
		options.Replace().SetUpsert(true))
	return err
}

func (m *MongoStore) DeleteUser(ctx context.Context, username string) error {
	_, err := m.users.DeleteOne(ctx, bson.D{{Key: "_id", Value: username}})
	return err
}

func (m *MongoStore) Close() error { return m.cli.Disconnect(context.Background()) }
