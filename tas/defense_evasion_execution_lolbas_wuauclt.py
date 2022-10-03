# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="2bb3bd72-8cdc-4025-b5f1-2bce7f57325c",
    platforms=["windows"],
    endpoint=[],
    siem=[{'rule_id': 'edf8ee23-5ea7-4123-ba19-56b41e424ae3', 'rule_name': 'ImageLoad via Windows Update Auto Update Client'}],
    techniques=[""],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(metadata.platforms)
def main():
    wuauclt = "C:\\Users\\Public\\wuauclt.exe"
    common.copy_file(EXE_FILE, wuauclt)

    # Execute command
    common.execute([wuauclt, "/c", "echo", "/RunHandlerComServer", "/UpdateDeploymentProvider", "C:\\Users\\a.dll"],
                   timeout=10)
    common.remove_file(wuauclt)


if __name__ == "__main__":
    exit(main())
