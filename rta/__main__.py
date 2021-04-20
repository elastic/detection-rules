# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import argparse
import importlib
import os

from . import get_ttp_names

parser = argparse.ArgumentParser("rta")
parser.add_argument("ttp_name")

parsed_args, remaining = parser.parse_known_args()
ttp_name, _ = os.path.splitext(os.path.basename(parsed_args.ttp_name))

if ttp_name not in get_ttp_names():
    raise ValueError("Unknown RTA {}".format(ttp_name))

module = importlib.import_module("rta." + ttp_name)
exit(module.main(*remaining))
