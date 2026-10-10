# Security Policy

## Supported versions

Security fixes go into the latest release.

## What KestrelAcme protects

KestrelAcme handles private keys: the ACME account key and the private key of every issued certificate.
The default store writes them to `AcmeOptions.StoragePath` with owner-only permissions on Linux and macOS.
On Windows the folder inherits the permissions of the user profile. Protect that folder (or your own
`IAcmeStore`) like any other secret.

## Reporting a vulnerability

Please **don't** open a public issue. Report it privately through
[GitHub security advisories](https://github.com/Monem-Benjeddou/KestrelAcme/security/advisories/new).
You should get a response within a week. Please give us a reasonable time to release a fix before you disclose it.
