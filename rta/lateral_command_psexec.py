# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: PsExec Lateral Movement
# RTA: lateral_command_psexec.py
# ATT&CK: T1035, T1077
# Description: Runs PSExec to move laterally

import sys

from . import common


@common.requires_os(common.WINDOWS)
@common.dependencies(common.PS_EXEC)
def main(remote_host=None):
    remote_host = remote_host or common.get_ip()
    common.log("Performing PsExec to %s" % remote_host)
    common.execute([common.PS_EXEC, "\\\\%s" % remote_host, "-accepteula", "ipconfig"])


if __name__ == "__main__":
    exit(main(*sys.argv[1:]))
