# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import urllib3


def validate_link(link: str):
    """Validate and return the link."""
    http = urllib3.PoolManager()
    response = http.request('GET', link)
    if response.status != 200:
        raise ValueError(f"Invalid link: {link}")
