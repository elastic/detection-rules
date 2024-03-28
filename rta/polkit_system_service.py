# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import sys

from . import RtaMetadata, common

metadata = RtaMetadata(
    uuid="32a4b4dd-24b3-4aed-bbce-2ca6ed5e1d69",
    platforms=["linux"],
    endpoint=[
        {
            "rule_id": "3144cab7-cc28-46c3-a3ac-8fefe8db22d6",
            "rule_name": "Privilege Escalation via Polkit System Service",
        },
    ],
    siem=[],
    techniques=["T1548"],
)


@common.requires_os(*metadata.platforms)
def main() -> None:
    masquerade = "/tmp/dbus-send"
    source = common.get_path("bin", "linux.ditto_and_spawn")
    common.copy_file(source, masquerade)

    # Execute command
    common.log("Executing Fake commands to test Privilege Escalation via Polkit System Service")
    common.execute(
        [
            masquerade,
            "--dest=org.freedesktop.Accounts",
            "org.freedesktop.Accounts.CreateUser",
            "org.freedesktop.Accounts.User.SetPassword",
            "org.freedesktop.Accounts.DeleteUser",
        ],
        timeout=10,
        kill=True,
    )

    # cleanup
    common.remove_file(masquerade)


if __name__ == "__main__":
    sys.exit(main())
