# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="3ede81fa-f4e7-48fc-a939-50ad7a9a07ca",
    platforms=["windows"],
    endpoint=[
        {"rule_name": "Command Shell Activity Started via RunDLL32", "rule_id": "b8a0a3aa-0345-4035-b41d-f758a6c59a78"},
        {"rule_name": "Execution from Unusual Directory", "rule_id": "16c84e67-e5e7-44ff-aefa-4d771bcafc0c"},
        {"rule_name": "RunDLL32 with Unusual Arguments", "rule_id": "cfaf983e-1129-464c-b0aa-270f42e20d3d"},
        {"rule_name": "Binary Proxy Execution via Rundll32", "rule_id": "f60455df-5054-49ff-9ff7-1dc4e37b6ea7"},
    ],
    siem=[],
    techniques=["T1218", "T1059"],
)


@common.requires_os(metadata.platforms)
def main():
    source_dll = "C:\\Windows\\System32\\IEAdvpack.dll"
    dll = "C:\\Users\\Public\\IEAdvpack.dll"
    common.copy_file(source_dll, dll)

    # Execute command
    common.log("Spawning cmd using Rundll32")
    common.execute(["rundll32.exe", f"{dll},RegisterOCX", "cmd.exe"])

    common.remove_files(dll)


if __name__ == "__main__":
    exit(main())
