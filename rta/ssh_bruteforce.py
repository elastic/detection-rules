# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata
from multiprocessing import Process


metadata = RtaMetadata(
    uuid="61369084-af6a-4fd0-903f-b44467f5d6e7",
    platforms=["macos"],
    endpoint=[],
    siem=[{"rule_name": "Potential SSH Brute Force Detected", "rule_id": "ace1e989-a541-44df-93a8-a8b0591b63c0"}],
    techniques=["T1110"],
)


def test(masquerade, masquerade2):
    common.execute([masquerade2, "childprocess", masquerade], timeout=0.3, kill=True)


@common.requires_os(metadata.platforms)
def main():

    masquerade = "/tmp/sshd-keygen-wrapper"
    masquerade2 = "/tmp/launchd"
    common.create_macos_masquerade(masquerade)
    common.create_macos_masquerade(masquerade2)

    # Execute command
    common.log("Launching fake ssh keygen commands to mimic ssh bruteforce")
    processes = []

    for i in range(25):
        p = Process(
            target=test,
            args=(
                masquerade,
                masquerade2,
            ),
        )
        processes.append(p)

    for i in processes:
        i.start()

    for i in processes:
        i.join()

    # cleanup
    common.remove_file(masquerade)
    common.remove_file(masquerade2)


if __name__ == "__main__":
    exit(main())
