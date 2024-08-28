# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import sys
from pathlib import Path

from . import RtaMetadata, common

metadata = RtaMetadata(
    uuid="41d3cdaf-a72e-49bb-b92f-99bfe21e0854",
    platforms=["linux"],
    endpoint=[
        {
            "rule_name": "Network Connection Followed by File Creation",
            "rule_id": "08ad673a-7f99-417e-8b93-a79d4faeeed3",
        },
    ],
    techniques=["T1071", "T1059"],
)


@common.requires_os(*metadata.platforms)
def main() -> None:
    script_path = "/dev/shm/evil"
    file_path = "/dev/shm/evil.txt"

    # Create a bash script that performs network connection and file creation
    script_content = f"""#!/bin/bash
# Perform network connection using bash built-in tools
exec 3<>/dev/tcp/8.8.8.8/53
# Create a file
echo "Hello, World!" > {file_path}
"""

    # Write the script content to the file
    with Path(script_path).open("w", encoding="utf-8") as script_file:
        script_file.write(script_content)

    # Grant execute permissions to the script
    Path(script_path).chmod(0o755)

    # Execute the script
    common.log("Executing the bash script...")
    common.execute([script_path], timeout=5, kill=True)

    # Verify if the file was created
    if Path(file_path).exists():
        common.log("File creation successful.")

    # Clean up
    common.log("Cleaning up...")
    common.remove_file(script_path)
    common.remove_file(file_path)
    common.log("Cleanup successful.")


if __name__ == "__main__":
    sys.exit(main())
