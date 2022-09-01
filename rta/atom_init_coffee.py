# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from pathlib import Path
from . import common

PLATFORMS = ["macos"]
TRIGGERED_RULES = {
    "SIEM": [
        {
            "rule_name": "Potential Persistence via Atom Init Script Modification",
            "rule_id": "b4449455-f986-4b5a-82ed-e36b129331f7",
        }
    ],
    "ENDPOINT": [],
}
TECHNIQUES = ["T1037"]
RTA_ID = "72c2470b-c96e-4b44-88ec-1a67c4ec091c"


@common.requires_os(PLATFORMS)
def main():

    atom_dir = Path.home().joinpath(".atom")
    atom_dir.mkdir(parents=True, exist_ok=True)
    atom_path = atom_dir.joinpath("init.coffee")
    common.log(
        f"Executing file modification on {atom_path} to mimic malicious Atom init file."
    )
    common.temporary_file_helper("testing", file_name=atom_path)

    # cleanup
    common.remove_directory(str(atom_dir))


if __name__ == "__main__":
    exit(main())
