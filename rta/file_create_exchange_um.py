# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from pathlib import Path

from . import RtaMetadata, common

metadata = RtaMetadata(
    uuid="29eb99a6-14cc-4d37-81dd-c2e78cda8c74",
    platforms=["windows"],
    endpoint=[],
    siem=[{
        'rule_id': '6cd1779c-560f-4b68-a8f1-11009b27fe63',
        'rule_name': 'Microsoft Exchange Server UM Writing Suspicious Files'
    }],
    techniques=['T1190'],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(*metadata.platforms)
def main():
    proc = "C:\\Users\\Public\\UMWorkerProcess.exe"
    path = "C:\\Users\\Public\\Microsoft\\Exchange Server Test\\FrontEnd\\HttpProxy\\owa\\auth\\"
    argpath = "C:\\Users\\Public\\Microsoft\\'Exchange Server Test'\\FrontEnd\\HttpProxy\\owa\\auth\\"
    common.copy_file(EXE_FILE, proc)
    Path(path).mkdir(parents=True, exist_ok=True)
    file = argpath + "\\shell.php"

    common.execute([proc, "/c", f"echo AAAAAAAA | Out-File {file}"], timeout=10, kill=True)
    common.remove_files(proc)


if __name__ == "__main__":
    exit(main())
