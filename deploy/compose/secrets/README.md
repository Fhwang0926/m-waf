# Runtime secrets

`prepare.sh` creates runtime secret files in this directory only when they do not already exist.

- Do not commit generated files.
- Keep the directory and files readable only by the deployment administrator.
- Back up the CA key pair, policy-signing key pair, and Manager data separately with encryption.
- Never run `docker compose down -v` in production.
