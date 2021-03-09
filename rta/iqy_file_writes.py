# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Suspicious IQY/PUB File Writes
# RTA: iqy_file_writes.py
# ATT&CK: T1140, T1192, T1193
# Description: Generates four file writes related to file extensions (PUB, IQY)

import os

from . import common


@common.requires_os(common.WINDOWS)
def main():
    common.log("Suspicious File Writes (IQY, PUB)")
    adobe_path = os.path.abspath("AcroRd32.exe")
    msoffice_path = os.path.abspath("winword.exe")
    browser_path = os.path.abspath("iexplore.exe")
    common.copy_file(common.CMD_PATH, adobe_path)
    common.copy_file(common.CMD_PATH, msoffice_path)
    common.copy_file(common.CMD_PATH, browser_path)
    common.log("Writing files")

    # write file as adobe, then run it
    common.log("Creating a 'suspicious' executable")
    bad_path = os.path.abspath("bad.exe")

    # PDF writing IQY file
    fake_iqy = os.path.abspath("test.iqy")
    common.execute([adobe_path, "/c", "echo", "test", ">", fake_iqy])

    # PDF writing PUB file
    fake_pub = os.path.abspath("test.pub")
    common.execute([adobe_path, "/c", "echo", "test", ">", fake_pub])

    # Winword writing IQY file
    fake_doc_iqy = os.path.abspath("test_word.iqy")
    common.execute([msoffice_path, "/c", "echo", "test", ">", fake_doc_iqy])

    # Brwoser writing IQY file
    fake_browser_iqy = os.path.abspath("test_browser.iqy")
    common.execute([browser_path, "/c", "echo", "test", ">", fake_browser_iqy])

    # cleanup
    common.remove_files(adobe_path, bad_path, fake_iqy)
    common.remove_files(adobe_path, bad_path, fake_pub)
    common.remove_files(msoffice_path, bad_path, fake_doc_iqy)
    common.remove_files(browser_path, bad_path, fake_browser_iqy)


if __name__ == "__main__":
    exit(main())
