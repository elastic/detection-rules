# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import os
import subprocess
import tempfile

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="9cb42759-a161-4d93-b07d-3c8254dc8838",
    platforms=["windows"],
    endpoint=[],
    siem=[{"rule_id": "55d551c6-333b-4665-ab7e-5d14a59715ce", "rule_name": "PsExec Network Connection"}],
    techniques=["T1569"],
)


@common.requires_os(metadata.platforms)
def main():
    temp_path = os.path.join(tempfile.gettempdir(), os.urandom(16).encode("hex"))
    sdelete_path = common.get_path("bin", "sdelete.exe")

    try:
        # Create a temporary file and close handles so it can be deleted
        with open(temp_path, "wb") as f_out:
            f_out.write("A")

        subprocess.check_call([sdelete_path, "/accepteula", temp_path])

    finally:
        common.remove_file(temp_path)


if __name__ == "__main__":
    exit(main())
