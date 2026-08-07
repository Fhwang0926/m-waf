# Runtime secrets

`prepare.sh` creates runtime secret files in this directory only when they do not already exist.

- Do not commit generated files.
- Keep this directory at mode `0700`. `prepare.sh` sets only Compose-mounted secret files to `0644` because the Manager runs as non-root UID/GID `65532` and local Compose file secrets preserve host ownership. The non-traversable directory keeps the files private from other host users.
- Do not change mounted secret files to `0600`; the Manager will fail with `permission denied` when reading `/run/secrets/*`.
- Back up the CA key pair, policy-signing key pair, and Manager data separately with encryption.
- Never run `docker compose down -v` in production.
- The first system administrator is created in the Admin UI and is stored in MariaDB as a password hash; no administrator password file is generated. Emergency recovery accepts a separate operator-managed password file through `reset-system-admin-password.sh` but never copies it into this secrets directory.
