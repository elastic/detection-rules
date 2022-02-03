# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Helper functionality for comparing semantic versions."""
import re
from typing import Iterable, Union


class Version(tuple):

    def __new__(cls, version: Union[str, Iterable]) -> 'Version':
        if isinstance(version, (int, list, tuple)):
            version_class = tuple.__new__(cls, version)
        else:
            version_tuple = tuple(int(a) if a.isdigit() else a for a in re.split(r'[.-]', version))
            version_class = tuple.__new__(cls, version_tuple)

        return version_class

    def __str__(self):
        """Convert back to a string."""
        recovered_str = str(self[0])
        for additional in self[1:]:
            if isinstance(additional, str):
                recovered_str += "-" + additional
            else:
                recovered_str += "." + str(additional)

        return recovered_str
