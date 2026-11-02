# Security notes

## URL investigation and SSRF boundary

Before a URL is submitted to TinyFish Fetch, the API:

- accepts only HTTP(S), bounds URL length, and rejects credentials, control
  characters, backslashes, scoped IP literals, and malformed authorities;
- rejects local hostnames and any literal IP address that is not globally
  routable;
- resolves hostnames and rejects a DNS answer set containing any non-global
  address;
- applies a 30-second total request deadline, shorter connection/read/write
  timeouts, a 20-second TinyFish per-URL budget, and a 5 MiB provider-response
  cap; and
- checks that returned pages correspond to submitted URLs and independently
  validates each reported final URL before returning page content to callers.

TinyFish Fetch performs the actual remote request. Its
[Fetch API reference](https://docs.tinyfish.ai/fetch-api/reference.md)
documents rejection of private IPs, localhost, and cloud metadata destinations,
and reports `final_url` plus `invalid_redirect_url` errors. This application
cannot inspect or approve every intermediate redirect before TinyFish follows
it, pin the provider's DNS resolution, or independently cap its redirect count.
The final-URL check is defense in depth after the provider request; it cannot
undo a request already made by the provider. Remote DNS rebinding and provider
redirect behavior therefore remain residual risks. Do not treat this URL
validation as a complete SSRF guarantee, and only submit URLs you are
authorized to investigate.

The application makes its provider requests only to fixed TinyFish and Google
Gemini API hosts. Gemini credentials are sent in a request header, not returned
to the frontend. TinyFish credentials are read from the process environment or
the local `.env` file and are not logged.

## Accounts and browser security

- Passwords use scrypt. Session tokens are random, stored as hashes, expire
  after 12 hours, and are revoked on logout or password change.
- Authentication uses a bearer token in the Streamlit server-to-server API
  request; the API does not issue browser authentication cookies. Cookie-based
  CSRF protections are therefore not applicable to this API flow. Do not move
  the token into a browser cookie without adding CSRF protections.
- Login attempts are limited per email. Public registration is limited to five
  attempts per observed client address per hour; only a one-way SHA-256 digest
  of that address is stored for this limiter. Configure rate limiting at the
  reverse proxy too, especially when several users share a proxy address.
- Admin role is read from the stored account record. Public registration
  cannot grant or request the admin role.
- User-owned investigations, saved reports, and watchlists are checked
  server-side. The database and host must still be protected from direct
  operator-level access.

## Hosting

Set `SCAMSHIELD_ALLOWED_HOSTS` to the exact API hostnames accepted by the
deployment, separated by commas. The default allows local development hosts
only. Keep TLS termination and public ingress at a trusted reverse proxy;
configure proxy forwarding only for known proxy addresses.

Use one FastAPI worker while the in-process watchlist scheduler is enabled.
SQLite is appropriate for this single-instance deployment, not shared
multi-instance writes. Mount the database on durable storage, restrict access,
and test backups and restore procedures. See [DEPLOYMENT.md](./DEPLOYMENT.md)
for startup and operations guidance.

## Verification limitations

The security review and automated tests are not a guarantee of security. Gemini
is optional; when it is unavailable the rule-based workflow remains available,
and provider errors are reported rather than replaced with invented analysis.
No public deployment, penetration test, or third-party dependency vulnerability
scan is implied by local checks.
