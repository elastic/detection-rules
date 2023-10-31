# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Suspicious IQY/PUB File Writes
# RTA: iqy_file_writes.py
# ATT&CK: T1140, T1192, T1193
# Description: Generates four file writes related to file extensions (PUB, IQY)

from pathlib import Path

from . import RtaMetadata, common

metadata = RtaMetadata(
    uuid="71f67037-1df3-4d5f-b8cb-eaf295ad16ed",
    platforms=["windows"],
    endpoint=[],
    siem=[],
    techniques=[]
)


@common.requires_os(*metadata.platforms)
def main():
    common.log("Suspicious File Writes (IQY, PUB)")
    adobe_path = Path("AcroRd32.exe").resolve()
    msoffice_path = Path("winword.exe").resolve()
    browser_path = Path("iexplore.exe").resolve()
    common.copy_file(common.CMD_PATH, adobe_path)
    common.copy_file(common.CMD_PATH, msoffice_path)
    common.copy_file(common.CMD_PATH, browser_path)
    common.log("Writing files")

    # write file as adobe, then run it
    common.log("Creating a 'suspicious' executable")
    bad_path = Path("bad.exe").resolve()

    # PDF writing IQY file
    fake_iqy = Path("test.iqy").resolve()
    common.execute([adobe_path, "/c", "echo", "test", ">", fake_iqy])

    # PDF writing PUB file
    fake_pub = Path("test.pub").resolve()
    common.execute([adobe_path, "/c", "echo", "test", ">", fake_pub])

    # Winword writing IQY file
    fake_doc_iqy = Path("test_word.iqy").resolve()
    common.execute([msoffice_path, "/c", "echo", "test", ">", fake_doc_iqy])

    # Browser writing IQY file
    fake_browser_iqy = Path("test_browser.iqy").resolve()
    common.execute([browser_path, "/c", "echo", "test", ">", fake_browser_iqy])

    # cleanup
    common.remove_files(adobe_path, bad_path, fake_iqy)
    common.remove_files(adobe_path, bad_path, fake_pub)
    common.remove_files(msoffice_path, bad_path, fake_doc_iqy)
    common.remove_files(browser_path, bad_path, fake_browser_iqy)


if __name__ == "__main__":
    exit(main())
