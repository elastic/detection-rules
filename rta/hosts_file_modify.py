# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Hosts File Modified
# RTA: hosts_file_modify.py
# ATT&CK: T1492
# Description: Modifies the hosts file

import os
import random
import time

from string import ascii_letters

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="f24491d0-720b-4150-a2a1-45b5b07238aa",
    platforms=["windows", "linux", "macos"],
    endpoint=[],
    siem=[{"rule_id": "9c260313-c811-4ec8-ab89-8f6530e0246c", "rule_name": "Hosts File Modified"}],
    techniques=["T1565"],
)


def main():
    hosts_files = {
        common.WINDOWS: "C:\\Windows\\system32\\drivers\\etc\\hosts",
        common.LINUX: "/etc/hosts",
        common.MACOS: "/private/etc/hosts",
    }
    hosts_file = hosts_files[common.CURRENT_OS]

    backup = os.path.abspath(hosts_file + "_backup")
    common.log("Backing up original 'hosts' file.")
    common.copy_file(hosts_file, backup)

    # add randomness for diffs for FIM module
    randomness = "".join(random.sample(ascii_letters, 10))
    entry = [
        "",
        "# RTA hosts_modify was here",
        "# 8.8.8.8 https://www.{random}.google.com".format(random=randomness),
    ]
    with open(hosts_file, "a") as f:
        f.write("\n".join(entry))

    common.log("Updated hosts file")
    with open(hosts_file, "r") as f:
        common.log(f.read())

    time.sleep(2)

    # cleanup
    common.log("Restoring hosts from backup copy.")
    common.copy_file(backup, hosts_file)
    os.remove(backup)


if __name__ == "__main__":
    exit(main())
