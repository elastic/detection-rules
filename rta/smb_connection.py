# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Outbound SMB from a User Process
# RTA: smb_connection.py
# ATT&CK: T1105
# Description: Initiates an SMB connection to a target machine, without going through the normal Windows APIs.

import socket
import sys

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="b0e3e1bb-dfa5-473a-8862-b2d1d42819ce",
    platforms=["windows"],
    endpoint=[],
    siem=[{"rule_id": "c82c7d8f-fb9e-4874-a4bd-fd9e3f9becf1", "rule_name": "Direct Outbound SMB Connection"}],
    techniques=["T1021"],
)


SMB_PORT = 445


@common.requires_os(metadata.platforms)
def main(ip=None):
    ip = ip or common.get_ip()

    # connect to rpc
    common.log("Connecting to {}:{}".format(ip, SMB_PORT))
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, 445))
    common.log("Sending HELLO")
    s.send(b"HELLO!")
    common.log("Shutting down the connection...")
    s.close()
    common.log("Closed connection to {}:{}".format(ip, SMB_PORT))


if __name__ == "__main__":
    exit(main(*sys.argv[1:]))
