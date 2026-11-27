# Certificate desk — review-only prototype

**Not production-ready and not a CA interface.** This project cannot issue, renew or revoke certificates, connect to step-ca, validate CSRs or policy, generate private keys, or automatically approve requests. Reviews are administrative records, **not authorization to issue**. Do not use this prototype to make certificate issuance decisions.

The prototype provides a web UI for storing PEM-shaped CSR submissions, manual review, directory login, administrator-defined informational profiles, settings and reviewed-request retention. Submitted CSRs are opaque and may be invalid or contain unsafe extensions and SANs. Profiles and their DNS suffixes and validity limits are **not enforced**. There is deliberately no route that signs or issues a certificate.

## Requirements and local preview

Node.js 22.13 or newer (the built-in SQLite module is experimental), npm, and optionally PostgreSQL. Install dependencies with `npm ci`. For a **loopback-only development preview**, generate a random encryption key with `openssl rand -base64 32` and set:

```sh
export ENCRYPTION_KEY='<32 random bytes encoded in standard base64>'
export MASTER_ADMIN_USER='admin'
export MASTER_ADMIN_PASSWORD='<unique password of at least 16 characters>'
export APP_ORIGIN='http://127.0.0.1:3000'
export ALLOW_INSECURE_LOCALHOST=1
export DATABASE_URL='sqlite:./app.db'
npm start
```

Open `http://127.0.0.1:3000`. Never expose the development mode to a network. Keep the encryption key stable and back it up separately from the database; changing or losing it makes encrypted configuration unreadable. The master admin credentials are deployment-time environment variables and are not stored in the database. Restart the process to change them; existing sessions remain valid for at most 15 minutes.

`DATABASE_URL` can instead be a PostgreSQL connection string (`postgresql://...`); protect transport and credentials using PostgreSQL's SSL settings. SQLite and PostgreSQL use the same schema; migrations beyond the initial schema are not implemented. PostgreSQL and a real LDAP server have not been integration-tested here.

## Reverse proxy and directory

For any non-local deployment, set `APP_ORIGIN` to the exact public HTTPS origin (without a path or trailing slash), leave `ALLOW_INSECURE_LOCALHOST` unset, and run behind a TLS-terminating reverse proxy. The application binds to `127.0.0.1` by default; keep its HTTP port inaccessible except to the trusted local proxy. For example, an illustrative nginx server block:

```nginx
server {
    listen 443 ssl;
    server_name desk.example.com;
    ssl_certificate /etc/ssl/desk/fullchain.pem;
    ssl_certificate_key /etc/ssl/desk/key.pem;
    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
    }
}
```

The application does not trust or use `X-Forwarded-*` headers. Its cookies are `Secure`, `HttpOnly`, and `SameSite=Strict` for HTTPS origins; state-changing API calls require the exact configured `Origin` and a session CSRF token. Configure TLS, security monitoring, network controls, backups, and rate limiting at the proxy too. The in-process login limit is per TCP peer and resets on process restart; behind a proxy it is shared by all clients and is not distributed.

An administrator may configure LDAP from the admin page. Only `ldaps://` with server certificate validation is accepted; an optional CA file must be readable by the server. Configure a service bind DN/password, base DN, a filter containing exactly one `{{username}}` placeholder (e.g. `(uid={{username}})`), group attribute (e.g. `memberOf`), and exact group DNs for roles. A successful unique search and user bind are required. Roles are selected by priority admin, approver, user; unmatched users are denied. Group DN comparison is case-insensitive exact string matching, not full LDAP DN normalization or nested-group resolution. Test the directory's returned attribute format before relying on it.

Sessions expire after 15 minutes, so directory membership changes may take up to 15 minutes to take effect; saving application settings invalidates all sessions immediately. Restarting with changed master credentials does not invalidate existing sessions. Administrators can create profiles and review other users' requests; approvers can review other users' requests; users can see only their own. LDAP identity is based on the returned DN to avoid username aliases bypassing self-review checks. Approvers and admins can read submitted CSRs, so never submit private keys.

The LDAP configuration, including bind password, is encrypted using AES-256-GCM with `ENCRYPTION_KEY`; it is not returned by the settings API. Other settings, CSR contents and reviews are stored unencrypted in the database. Configure filesystem/database access and backups accordingly.

## Retention and limitations

Reviewed requests are deleted after the configured retention period (default 90 days), on startup and hourly. Pending requests are retained indefinitely. This removes database rows, not necessarily data from SQLite WAL files, database pages, replicas or backups; handle backup retention and secure deletion separately. No certificates or private keys are created or persisted by this prototype.

Before any real issuance implementation, validate the immutable CSR signature, actual subject and **every SAN and extension**, public-key algorithm and size, and a strictly enforced policy at approval and issuance. Bind approvals transactionally to the exact CSR and policy version, prevent self-approval, enforce current role membership, and handle retries and external CA failures safely. Optional generated private keys would need owner-only delivery and encrypted storage with explicit retention. A step-ca integration must use a pinned CA root and a properly scoped JWK provisioner; `step ca token --cnf-file` can bind a token to the CSR and `step ca sign` signs it. See the official [token reference](https://github.com/smallstep/docs/blob/master/step-cli/reference/ca/token/README.mdx) and [sign reference](https://github.com/smallstep/docs/blob/master/step-cli/reference/ca/sign/README.mdx). No such integration exists or has been verified here.

## Tests

Run `npm test` and `npm audit --omit=dev`. Tests cover the SQLite-backed API, authentication, RBAC, CSRF, ownership, concurrent review, encrypted configuration and retention. They do not prove LDAP, PostgreSQL, reverse-proxy, or CA interoperability.
