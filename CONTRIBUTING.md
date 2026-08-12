# Contributing

1. Open an issue describing the user problem and expected behavior.
2. Keep pull requests focused and include tests for collectors, parsers, diff rules, or CLI behavior.
3. Run `make verify` before submitting.
4. Never commit real infrastructure inventories, credentials, private keys, or production hostnames.
5. Preserve stable resource IDs and JSON compatibility unless the change is explicitly documented as breaking.

Linux collectors should degrade gracefully when optional tools or permissions are unavailable. Add fixture coverage when a change can be reproduced without a live Linux host.
