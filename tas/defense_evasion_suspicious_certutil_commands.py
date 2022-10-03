# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="4d830a40-7a14-42f4-936c-30076201f9ef",
    platforms=["windows"],
    endpoint=[],
    siem=[{'rule_id': 'fd70c98a-c410-42dc-a2e3-761c71848acf', 'rule_name': 'Suspicious CertUtil Commands'}],
    techniques=[""],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(metadata.platforms)
def main():
    certutil = "C:\\Users\\Public\\certutil.exe"
    common.copy_file(EXE_FILE, certutil)

    # Execute command
    common.execute([certutil, "/c", "echo", "/decode"], timeout=10)
    common.remove_file(certutil)


if __name__ == "__main__":
    exit(main())
