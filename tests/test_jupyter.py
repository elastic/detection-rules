# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Test Jupyter."""

import sys
import unittest

from detection_rules import jupyter

cells_markdown = [
    ("# Title", {
        "cell_type": "markdown",
        "id": "1c3720e2",
        "metadata": {},
        "source": [
            "# Title",
        ],
    }),
]

cells_code = [
    ("x=0", None, {
        "cell_type": "code",
        "id": "215fb9d0",
        "metadata": {},
        "execution_count": 1,
        "source": [
            "x=0",
        ],
        "outputs": [],
    }),

    ("print('Hello, world!')", "Hello, world!", {
        "cell_type": "code",
        "id": "518c687f",
        "metadata": {},
        "execution_count": 2,
        "source": [
            "print('Hello, world!')",
        ],
        "outputs": [{
            "data": {
                "text/plain": ["Hello, world!"],
            },
            "execution_count": 2,
            "metadata": {},
            "output_type": "execute_result",
        }],
    }),
]

notebooks = [
    ([], {
        "cells": [],
        "metadata": {
            "language_info": {
                "file_extension": ".py",
                "mimetype": "text/x-python",
                "name": "python",
                "version": ".".join(str(v) for v in sys.version_info[:3]),
            },
        },
        "nbformat": 4,
        "nbformat_minor": 5,
    })
]

class TestJupyter(unittest.TestCase):
    maxDiff = None

    def subTest(self, *args, **kwargs):
        jupyter.random.seed(str(args[0]))
        return super(TestJupyter, self).subTest(*args, **kwargs)

    def test_markdown(self):
        for markdown,cell in cells_markdown:
            with self.subTest(markdown):
                self.assertEqual(cell, jupyter.Markdown(markdown))

    def test_code(self):
        for i,(code,output,cell) in enumerate(cells_code):
            with self.subTest(code):
                self.assertEqual(cell, jupyter.Code(code, output, execution_count=i+1))

    def test_notebook(self):
        for cells,nb in notebooks:
            with self.subTest(cells):
                self.assertEqual(nb, jupyter.to_notebook(cells))
