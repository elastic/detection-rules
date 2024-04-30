# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Reading sensitive files
# RTA: linux_discovery_sensitive_files.py
# Description: Uses built-in commands for *nix operating systems to read known sensitive
#              files, such as etc/shadow and etc/passwd
from . import common
from . import RtaMetadata


metadata = RtaMetadata(uuid="82358d3d-6f04-42d0-a182-db37cf98294e", platforms=["linux"], endpoint=[], siem=[], techniques=[])


@common.requires_os(*metadata.platforms)
def main():
    common.log("Reading sensitive files", log_type="~")

    # Launch an interactive shell with redirected stdin, to simulate interactive shell access
    common.execute(
        "/bin/sh",
        stdin="""
    cat /etc/sudoers
    cat /etc/group
    cat /etc/passwd
    cat /etc/shadow
    """,
    )


if __name__ == "__main__":
    main()
