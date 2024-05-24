# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata
import os
import socket

metadata = RtaMetadata(
    uuid="d1ad870e-9b38-429b-bc9c-62b4b9ba2821",
    platforms=["linux"],
    endpoint=[
        {
            "rule_name": "Python Network Connection Followed by File Creation",
            "rule_id": "1a2596ff-a5e7-4562-af17-97dbaf9284d5"
        }
    ],
    techniques=["T1071", "T1059"],
)


@common.requires_os(*metadata.platforms)
def main():

    # Define the paths
    masquerade = "/dev/shm/python"
    file_path = "/dev/shm/file.txt"

    # Create a fake Python executable by copying a valid executable
    with open(masquerade, 'w') as f:
        f.write("#!/bin/bash\n")
        f.write("exec python \"$@\"\n")

    # Grant execute permissions
    os.chmod(masquerade, 755)

    # Perform a network connection to 8.8.8.8
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        sock.connect(("8.8.8.8", 53))
        sock.close()
        print("Network connection successful.")
    except Exception as e:
        print(f"Network connection failed: {e}")

    # Create a file using the Python process
    try:
        with open(file_path, 'w') as f:
            f.write("foo")
        print("File creation successful.")
    except Exception as e:
        print(f"File creation failed: {e}")

    # Clean up
    try:
        os.remove(masquerade)
        os.remove(file_path)
        print("Cleanup successful.")
    except Exception as e:
        print(f"Cleanup failed: {e}")


if __name__ == "__main__":
    exit(main())
