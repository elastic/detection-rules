# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="ce7f34b7-dfe4-424b-8888-d488329ac58e",
    platforms=["windows"],
    endpoint=[],
    siem=[{'rule_id': '7b8bfc26-81d2-435e-965c-d722ee397ef1', 'rule_name': 'Windows Network Enumeration'}],
    techniques=[""],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(metadata.platforms)
def main():
    net = "C:\\Users\\Public\\net.exe"
    common.copy_file(EXE_FILE, net)

    # Execute command
    common.execute([net, "/c", "echo", "view"], timeout=10)
    common.remove_file(net)


if __name__ == "__main__":
    exit(main())
