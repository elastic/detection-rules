# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License;
# you may not use this file except in compliance with the Elastic License.

import os
import subprocess
import tempfile

from . import common


@common.requires_os(common.WINDOWS)
def main():
    temp_path = os.path.join(tempfile.gettempdir(), os.urandom(16).encode('hex'))
    sdelete_path = common.get_path("bin", 'sdelete.exe')

    try:
        # Create a temporary file and close handles so it can be deleted
        with open(temp_path, 'wb') as f_out:
            f_out.write('A')

        subprocess.check_call([sdelete_path, '/accepteula', temp_path])

    finally:
        common.remove_file(temp_path)


if __name__ == "__main__":
    exit(main())
