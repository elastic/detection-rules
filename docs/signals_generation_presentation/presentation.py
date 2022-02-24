# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Helper for the presentation."""

import os
import random

presentation_dir = os.path.split(__file__)[0]
os.chdir(os.path.abspath(os.path.join(presentation_dir, "..", "..")))

random.seed("presentation")
