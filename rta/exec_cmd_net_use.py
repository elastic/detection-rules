# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="46f6ae71-2fd8-46bd-8209-9fc0f59432ef",
    platforms=["windows"],
    endpoint=[],
    siem=[{'rule_id': 'c4210e1c-64f2-4f48-b67e-b5a8ffe3aa14', 'rule_name': 'Mounting Hidden or WebDav Remote Shares'}],
    techniques=['T1021', 'T1021.002', 'T1078', 'T1078.003'],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(*metadata.platforms)
def main():
    net = "C:\\Users\\Public\\net.exe"
    common.copy_file(EXE_FILE, net)

    # Execute command
    common.execute([net, "/c", "echo", "use", "http"], timeout=10)
    common.remove_file(net)


if __name__ == "__main__":
    exit(main())
