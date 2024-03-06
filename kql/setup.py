# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.
from setuptools import setup

setup(
    name="detection-rules-kql",
    version="0.1.6",
    py_modules=["ast", "dsl", "eql2kql", "errors", "evaluator", "kql2eql", "optimizer", "parser", "__init__"],
    install_requires=[
        "eql==0.9.19",
        "lark-parser>=0.11.1",
    ],
    package_data={
        'kql': ['*.g'],
    },
    include_package_data=True,
)
