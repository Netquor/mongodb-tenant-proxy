# Cross-driver compatibility suite

`./run.sh [mongosh|node|python|java ...]` builds the proxy binary, starts it in
`appname` mode and in `static` mode (one proxy per tenant), and runs each
language's scenario against both: CRUD, bulk writes, `$lookup`, transactions,
change streams, index creation (unique per tenant), and assertions that two
tenants never see each other's data. Node also runs a Mongoose smoke test
(`autoIndex`) and handshake-option probes (serverApi, compression, ...).

Upstream is a throwaway local `mongod` replica set (`MTP_MONGOD_BIN` to pick
the binary) or an existing initiated single-node replica set via
`MTP_MONGO_ADDR=host:port`. Change streams need MongoDB 6.0+; on older
upstreams the scenarios assert the proxy answers `CommandNotSupported` (115).

Requirements: `mongosh`, `node`/`npm`, `python3`, and JDK 17+ with `mvn`.
`.github/scripts/start-mongo.sh <version> [port]` starts a dockerised upstream.
