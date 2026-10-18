# systemd

```sh
sudo useradd --system --no-create-home --shell /usr/sbin/nologin mtproxy
sudo make install
sudo cp proxy.example.json /etc/mongodb-tenant-proxy/proxy.json    # edit it
sudo install -m 0600 -o mtproxy /dev/null /etc/mongodb-tenant-proxy/env  # MTP_UPSTREAM_PASSWORD=...
sudo systemctl enable --now mongodb-tenant-proxy
sudo systemctl reload mongodb-tenant-proxy     # SIGHUP: hot-reload proxy.json
```

State (`store.path`, e.g. `/var/lib/mongodb-tenant-proxy/tenants.json`) and audit
logs (`/var/log/mongodb-tenant-proxy/audit.log`) are the only writable paths.
