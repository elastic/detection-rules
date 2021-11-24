# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Functions for generating fuzzy behavior."""

import random
import string

__all__ = (
    "expand_wildcards",
    "fuzzy_choice",
    "fuzzy_iter",
    "get_random_string",
)

fuzziness = 0

def get_random_string(min_length, condition=None, allowed_chars=string.ascii_letters):
    l = random.choices(allowed_chars, k=min_length)
    while condition and not condition("".join(l)):
        l.insert(random.randrange(len(l)), random.choice(allowed_chars))
    return "".join(l)

def get_random_octets(n):
    return [random.randint(1, 254) for _ in range(n-1)]

def fuzzy_ip(nr_octets, sep, fmt, condition = None):
    if fuzziness:
        octets = get_random_octets(nr_octets)
    else:
        octets = [1] * nr_octets
    def to_str(o):
        return sep.join(fmt.format(x) for x in o)
    while condition and not condition(to_str(octets)):
        octets = get_random_octets(nr_octets)
    return to_str(octets)

def fuzzy_ipv4(*args, **kwargs):
    return fuzzy_ip(4, ".", "{:d}")

def fuzzy_ipv6(*args, **kwargs):
    return fuzzy_ip(6, ":", "{:x}")

def fuzzy_choice(options):
    if fuzziness:
        return random.choice(options)
    else:
        return options[0]

def fuzzy_iter(iterable):
    # shortcut: should shuffle randomly
    return iterable

def expand_wildcards(s, allowed_chars=string.ascii_letters+string.digits):
    chars = []
    for c in list(s):
        if c == '?':
            chars.append(random.choice(allowed_chars))
        elif c == "*":
            chars.extend(random.choices(allowed_chars, k=random.randrange(16)))
        else:
            chars.append(c)
    return "".join(chars)
