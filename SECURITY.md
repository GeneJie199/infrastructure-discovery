# Security Policy

## Reporting a vulnerability

Do not include credentials, private inventories, or production snapshots in a public issue. Report security problems privately to the repository maintainer through GitHub's private vulnerability reporting when available.

Include the affected version, operating system, reproduction steps, and a minimally redacted example.

## Data handling

InfraScout is local-first and does not upload scan data. It redacts common secret-bearing command-line values, but inventories still contain operational metadata such as paths, usernames, images, ports, and service names. Treat generated JSON as sensitive infrastructure data.

The embedded viewer has no authentication and listens on `127.0.0.1` by default. Use an SSH tunnel or an authenticated reverse proxy for remote access.
