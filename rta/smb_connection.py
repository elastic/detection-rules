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

SMB_PORT = 445


@common.requires_os(common.WINDOWS)
def main(ip=None):
    ip = ip or common.get_ip()

    # connect to rpc
    common.log("Connecting to {}:{}".format(ip, SMB_PORT))
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, 445))
    common.log("Sending HELLO")
    s.send(b"HELLO!")
    common.log("Shutting down the conection...")
    s.close()
    common.log("Closed connection to {}:{}".format(ip, SMB_PORT))


if __name__ == "__main__":
    exit(main(*sys.argv[1:]))
