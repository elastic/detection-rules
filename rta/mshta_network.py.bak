# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License;
# you may not use this file except in compliance with the Elastic License.

# Name: Microsoft HTA tool (mshta.exe) with Network Callback
# RTA: mshta_network.py
# ATT&CK: T1170
# Description: Generates network traffic from mshta.exe

from . import common

HTA_FILE = common.get_path("bin", "beacon.hta")


@common.requires_os(common.WINDOWS)
@common.dependencies(HTA_FILE)
def main():
    # http server will terminate on main thread exit
    # if daemon is True
    common.log("MsHta Beacon")
    server, ip, port = common.serve_web()
    common.clear_web_cache()

    new_callback = "http://%s:%d" % (ip, port)
    common.log("Updating the callback to %s" % new_callback)
    common.patch_regex(HTA_FILE, common.CALLBACK_REGEX, new_callback)

    mshta = 'mshta.exe'
    common.execute([mshta, HTA_FILE], timeout=3, kill=True)
    server.shutdown()


if __name__ == "__main__":
    exit(main())
