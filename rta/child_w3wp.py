# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="be6619a2-324a-443b-9f23-2dc84733c847",
    platforms=["windows"],
    endpoint=[
        {"rule_name": "Suspicious Microsoft IIS Worker Descendant", "rule_id": "89c9c5a0-a136-41e9-8cc8-f21ef5ad894b"}
    ],
    siem=[],
    techniques=["T1190", "T1059"],
)

EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(metadata.platforms)
def main():
    w3wp = "C:\\Users\\Public\\w3wp.exe"
    common.copy_file(EXE_FILE, w3wp)

    # Creating a high entropy file, and executing the rename operation
    common.execute([w3wp, "/c", "cmd.exe"], timeout=10)
    common.remove_file(w3wp)


if __name__ == "__main__":
    exit(main())
