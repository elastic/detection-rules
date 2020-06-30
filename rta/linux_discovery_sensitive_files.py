# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License;
# you may not use this file except in compliance with the Elastic License.

# Name: Reading sensitive files
# RTA: linux_discovery_sensitive_files.py
# Description: Uses built-in commands for *nix operating systems to read known sensitive
#              files, such as etc/shadow and etc/passwd
from . import common


@common.requires_os(common.LINUX)
def main():
    common.log("Reading sensitive files", log_type="~")

    # Launch an interactive shell with redirected stdin, to simulate interactive shell access
    common.execute('/bin/sh', stdin="""
    cat /etc/sudoers
    cat /etc/group
    cat /etc/passwd
    cat /etc/shadow
    """)


if __name__ == '__main__':
    main()
