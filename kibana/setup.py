# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.
from setuptools import setup, find_packages

setup(
    name="detection-rules-kibana",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "requests>=2.25,<3.0",
        "elasticsearch~=8.1",
    ]
)
