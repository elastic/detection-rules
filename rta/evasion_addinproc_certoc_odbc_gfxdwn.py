# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="6e84852e-b8a2-4158-971e-c5148d969d2a",
    platforms=["windows"],
    siem=[],
    endpoint=[
          {'rule_id': '5bc7a8f8-4de8-4af4-bea4-cba538e54a5c', 'rule_name': 'Suspicious Execution via DotNet Remoting'},
          {'rule_id': '6fcbf73f-4413-4689-be33-61b0d6bd0ffc', 'rule_name': 'Suspicious ImageLoad via Windows CertOC'},
          {'rule_id': '1faebe83-38d7-4390-b6bd-9c6b851e47c4', 'rule_name': 'Suspicious ImageLoad via ODBC Driver Configuration Program'},
          {'rule_id': 'aafe3c78-15d9-4853-a602-663b8fada5b5', 'rule_name': 'Potential Evasion via Intel GfxDownloadWrapper'}],
    techniques=['T1218', 'T1218.008', 'T1105'],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(*metadata.platforms)
def main():
    addinproc = "C:\\Users\\Public\\AddInProcess.exe"
    certoc = "C:\\Users\\Public\\CertOc.exe"
    odbc = "C:\\Users\\Public\\odbcconf.exe"
    gfxdwn = "C:\\Users\\Public\\GfxDownloadWrapper.exe"

    common.copy_file(EXE_FILE, addinproc)
    common.copy_file(EXE_FILE, certoc)
    common.copy_file(EXE_FILE, odbc)
    common.copy_file(EXE_FILE, gfxdwn)

    # Execute command
    common.execute([addinproc, "/guid:32a91b0f-30cd-4c75-be79-ccbd6345de99", "/pid:123"], timeout=10)
    common.execute([certoc, "-LoadDLL"], timeout=10)
    common.execute([odbc, "-a", "-f"], timeout=10)
    common.execute([gfxdwn, "run", "2", "0"], timeout=10)

    # Cleanup
    common.remove_file(addinproc)
    common.remove_file(certoc)
    common.remove_file(odbc)
    common.remove_file(gfxdwn)


if __name__ == "__main__":
    exit(main())
