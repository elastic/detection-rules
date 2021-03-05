# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License;
# you may not use this file except in compliance with the Elastic License.

"""Helper functionality for comparing semantic versions."""
import re
from typing import Iterable, Optional, Union


class Version(tuple):

    def __new__(cls, version: Union[Iterable, str], pad: Optional[int] = None) -> 'Version':
        if not isinstance(version, (int, list, tuple)):
            version = tuple(int(a) if a.isdigit() else a for a in re.split(r'[.-]', version))

            if pad:
                width = len(version)

                if pad > width:
                    version = version + (0,) * (pad - width)

        return version if isinstance(version, int) else tuple.__new__(cls, version)

    def bump(self):
        """Increment the version."""
        versions = list(self)
        versions[-1] += 1
        return Version(versions)

    def __str__(self):
        """Convert back to a string."""
        return ".".join(str(dig) for dig in self)
