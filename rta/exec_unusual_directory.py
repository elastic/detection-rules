# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="0860c487-e9e0-4f86-9829-5bb98f615046",
    platforms=["windows"],
    endpoint=[
        {"rule_name": "Execution from Unusual Directory", "rule_id": "16c84e67-e5e7-44ff-aefa-4d771bcafc0c"},
        {"rule_name": "Binary Masquerading via Untrusted Path", "rule_id": "35dedf0c-8db6-4d70-b2dc-a133b808211f"},
    ],
    siem=[],
    techniques=["T1218", "T1036", "T1059"],
)


@common.requires_os(metadata.platforms)
def main():
    exe_path = "c:\\windows\\system32\\cscript.exe"
    binary = "c:\\Users\\Public\\cscript.exe"
    common.copy_file(exe_path, binary)

    # Execute command
    common.log("Executing cscript from unusual directory")
    common.execute([binary], timeout=5, kill=True)

    common.remove_files(binary)


if __name__ == "__main__":
    exit(main())
