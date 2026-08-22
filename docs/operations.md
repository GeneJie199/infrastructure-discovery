# InfraScout Operations Guide

## Production workflow

1. Download the release binary for the target platform.
2. Install it with `sudo ./install.sh ./infrascout-linux-amd64`.
3. Run the one-command first start. It scans, initializes an approved baseline and current state, starts the viewer, and opens the browser:

   ```bash
   sudo infrascout up --state-dir /var/lib/infrascout --no-open
   ```

4. Run a one-off release check:

   ```bash
   sudo infrascout check --state-dir /var/lib/infrascout --fail-on warning
   ```

5. Start continuous local monitoring:

   ```bash
   sudo infrascout watch \
     --state-dir /var/lib/infrascout \
     --addr 127.0.0.1:8765 \
     --interval 1m
   ```

   To refresh read-only database metadata in the same loop, expose the DSN through the service environment and add `--database-engine postgres` or `--database-engine mysql`. Database drift then participates in the same review decisions and `check --fail-on` gate.

   PostgreSQL constraints and triggers use read-only system catalogs; views, routines, and privileges remain limited to what the account can see. MySQL exposes triggers only with the target database `TRIGGER` privilege and exposes complete users/roles only with `SELECT` on `mysql.user`. Missing optional metadata is recorded in `warnings`. InfraScout always opens a read-only transaction and never selects business table rows.

The viewer deliberately binds to loopback. Access a remote host through an SSH tunnel:

```bash
ssh -L 8765:127.0.0.1:8765 user@server
```

Then open `http://127.0.0.1:8765/` locally.

## systemd

After creating the baseline, install the example unit:

```bash
sudo install -m 0644 deploy/infrascout.service /etc/systemd/system/infrascout.service
sudo systemctl daemon-reload
sudo systemctl enable --now infrascout
sudo systemctl status infrascout
```

The unit can read Docker metadata because it runs as root, but it is otherwise hardened and may only write `/var/lib/infrascout`.

## State files

| File | Purpose |
|---|---|
| `baseline.json` | Operator-approved comparison baseline |
| `current.json` | Most recent comparable snapshot |
| `inventory.json` | Most recent resource inventory |
| `drift.json` | Most recent severity-aware comparison |
| `decisions.json` | Audited expected/approved/temporary/unexpected/denied decisions |
| `database-baseline.json` | Approved read-only database metadata baseline |
| `database-current.json` | Most recent read-only database metadata |
| `database-diff.json` | Constraint, role, privilege, and structural database drift |

Writes use a temporary file followed by rename so the viewer never reads a partially written document on Linux.

## Backup and restore

Stop the watcher before taking a consistent backup, then archive the complete state directory. It contains approved baselines, current observations, review decisions, and optional database metadata; it never contains the database DSN.

```bash
sudo systemctl stop infrascout
sudo tar -C /var/lib -czf infrascout-state-$(date +%F).tgz infrascout
sudo systemctl start infrascout
```

Restore onto the same or a replacement host only after reviewing the hostname and baseline ownership. Extract into a temporary directory, verify `baseline.json` and `decisions.json`, then replace `/var/lib/infrascout` while the service is stopped.

## Exit behavior

`check --fail-on critical` fails only for critical drift. The accepted values are `critical`, `warning`, `info`, and `never`. This makes the command suitable for CI/CD release gates.

## Security

- Passwords, tokens, API keys, secrets, credential-bearing URLs, and common secret environment variables are redacted from collected command lines.
- The viewer has no authentication and therefore defaults to loopback. Do not bind it to `0.0.0.0` without an authenticated reverse proxy and network policy.
- Non-root scans remain useful, but Docker socket access and some process-to-port associations may be unavailable. These limitations appear in `warnings` instead of failing the scan.
- Review inventory data before sharing it outside the host. Paths, usernames, images, and service names can still be operationally sensitive.

## Baseline policy

Do not automatically replace `baseline.json` after every deployment. Run `baseline` only after a human or release pipeline has reviewed and accepted the reported drift.
