# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Functions for generating fuzzy behavior."""

import random
import contextlib

__all__ = (
    "fuzziness",
    "fuzzy_choice",
    "fuzzy_iter",
)

fuzziness_level = 1

def fuzziness(level=None):
    global fuzziness_level
    if level is None:
        return fuzziness_level
    @contextlib.contextmanager
    def _fuzziness(level):
        global fuzziness_level
        orig_level, fuzziness_level = fuzziness_level, level
        try:
            yield
        finally:
            fuzziness_level = orig_level
    return _fuzziness(level)

def fuzzy_choice(options):
    if fuzziness_level:
        return random.choice(options)
    else:
        return options[0]

def fuzzy_iter(iterable):
    if fuzziness_level:
        return random.sample(iterable, len(iterable))
    else:
        return iterable
