# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License;
# you may not use this file except in compliance with the Elastic License.

# Name: Compression of sensitive files
# RTA: linux_compress_sensitive_files.py
# Description: Uses built-in commands for *nix operating systems to compress known sensitive
#              files, such as etc/shadow and etc/passwd
from . import common


@common.requires_os(common.LINUX)
def main():
    common.log("Compressing sensitive files")
    files = ['totally-legit.tar', 'official-business.zip', 'expense-reports.gz']

    # we don't want/need these to actually work, since the rule is only looking for command line, so no need for sudo
    commands = [
        ['tar', '-cvf', files[0], '/etc/shadow'],
        ['zip', files[1], '/etc/passwd'],
        ['gzip', '/etc/group', files[2]]
    ]
    for command in commands:
        try:
            common.execute(command)
        except OSError as exc:
            # command doesn't exist on distro - the rule only needs one to trigger
            # also means we will eventually need to explore per distro ground truth when we expand as counts will vary
            common.log(str(exc))


if __name__ == '__main__':
    main()
