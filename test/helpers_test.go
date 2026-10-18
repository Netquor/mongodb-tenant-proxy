package test

import (
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/writeconcern"

	"github.com/netquor/mongodb-tenant-proxy/internal/auth"
)

type writeConcernT = writeconcern.WriteConcern

func writeConcernW0() *writeConcernT { return writeconcern.Unacknowledged() }

func signed(secret, tenant string) string { return auth.SignTenant(secret, tenant) }

func optionsUnordered() *options.ClientBulkWriteOptionsBuilder {
	return options.ClientBulkWrite().SetOrdered(false)
}
