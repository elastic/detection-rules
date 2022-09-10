# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Microsoft HTA tool (mshta.exe) with Network Callback
# RTA: mshta_network.py
# ATT&CK: T1170
# Description: Generates network traffic from mshta.exe

from . import common
from . import RtaMetadata

HTA_FILE = common.get_path("bin", "beacon.hta")


metadata = RtaMetadata(
    uuid="83465fca-25ae-4d6d-b747-c82cda75b0ae",
    platforms=["windows"],
    endpoint=[],
    siem=[
        {
            "rule_id": "1fe3b299-fbb5-4657-a937-1d746f2c711a",
            "rule_name": "Unusual Network Activity from a Windows System Binary",
        },
        {"rule_id": "c2d90150-0133-451c-a783-533e736c12d7", "rule_name": "Mshta Making Network Connections"},
        {"rule_id": "a4ec1382-4557-452b-89ba-e413b22ed4b8", "rule_name": "Network Connection via Mshta"},
    ],
    techniques=["T1127", "T1218"],
)


@common.requires_os(metadata.platforms)
@common.dependencies(HTA_FILE)
def main():
    # http server will terminate on main thread exit
    # if daemon is True
    common.log("MsHta Beacon")
    server, ip, port = common.serve_web()
    common.clear_web_cache()

    new_callback = "http://%s:%d" % (ip, port)
    common.log("Updating the callback to %s" % new_callback)
    common.patch_regex(HTA_FILE, common.CALLBACK_REGEX, new_callback)

    mshta = "mshta.exe"
    common.execute([mshta, HTA_FILE], timeout=3, kill=True)
    server.shutdown()


if __name__ == "__main__":
    exit(main())
