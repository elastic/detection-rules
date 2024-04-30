# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import platform
from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="f1321e5c-101d-4b03-8f0c-6cf8bda174ec",
    platforms=["macos"],
    endpoint=[
        {
            "rule_name": "Collect DIAG Dylib Load Event",
            "rule_id": "2df75424-4106-43c5-8fea-f115e18588da",
        },
        {
            "rule_name": "Dylib Injection via Process Environment Variables",
            "rule_id": "246741d4-3eee-4fbb-beec-53ef562c62c3",
        },
        {
            "rule_name": "Potential Binary Masquerading via Invalid Code Signature",
            "rule_id": "4154c8ce-c718-4641-80db-a6a52276f1a4",
        },
    ],
    siem=[],
    techniques=["T1574", "T1574.006"],
)


@common.requires_os(*metadata.platforms)
def main():

    if platform.processor() == "arm":
        name = "com.apple.sleep_arm"
        dylib = "inject_arm.dylib"
    else:
        name = "com.apple.sleep_intel"
        dylib = "inject_intel.dylib"
    target_bin = common.get_path("bin", name)
    common.execute([f"DYLD_INSERT_LIBRARIES={dylib}", target_bin, "5"], kill=True, shell=True)


if __name__ == "__main__":
    exit(main())
