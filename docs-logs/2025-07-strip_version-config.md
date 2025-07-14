## Add strip_version config support

Implemented reading `strip_version` from `_config.yaml` and applying it during rule export. The option mirrors `--strip-version` on the CLI and removes `version` and `revision` fields from exported rules. Documentation was updated and the option can also be used via the CLI flag or configuration file.
