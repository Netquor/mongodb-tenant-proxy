# docker-compose example

```sh
export MTP_ADMIN_TOKEN=$(openssl rand -hex 24)
docker compose -f deploy/compose/docker-compose.yml up --build -d

# create a tenant and a user (the generated password is shown once)
curl -s -H "Authorization: Bearer $MTP_ADMIN_TOKEN" -d '{"id":"acme"}' localhost:9103/v1/tenants
curl -s -H "Authorization: Bearer $MTP_ADMIN_TOKEN" -d '{"username":"acme-app"}' localhost:9103/v1/tenants/acme/users

mongosh "mongodb://acme-app:<password>@localhost:27018/?authMechanism=SCRAM-SHA-256&authSource=admin"
```

The proxy runs without upstream credentials here (the example mongod has auth
off). For an authenticated deployment add `upstream.username` and set
`MTP_UPSTREAM_PASSWORD`.
