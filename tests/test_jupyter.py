# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Test Jupyter."""

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
            },
        },
        "nbformat": 4,
        "nbformat_minor": 5,
    })
]

md_markdown = [
    ("# Title", [
        "# Title",
    ]),

    ("""
        * bullet
        * bullet
        * bullet
    """, [
        "* bullet\n",
        "* bullet\n",
        "* bullet",
    ]),
]

md_code = [
    ("x=0", None, [
        "```python\n",
        "x=0\n",
        "```\n\n",
    ]),

    ("print('Hello, world!')", "Hello, world!", [
        "```python\n",
        "print('Hello, world!')\n",
        "```\n\n",
        "```python\n",
        "Hello, world!\n",
        "```\n\n",
    ]),
]

class TestJupyter(unittest.TestCase):
    maxDiff = None

    def subTest(self, *args, **kwargs):
        jupyter.random.seed(str(args[0]))
        return super(TestJupyter, self).subTest(*args, **kwargs)

    def test_markdown(self):
        for markdown,cell in cells_markdown:
            with self.subTest(markdown):
                self.assertEqual(cell, jupyter.Markdown(markdown).to_cell())

    def test_code(self):
        for i,(code,output,cell) in enumerate(cells_code):
            with self.subTest(code):
                self.assertEqual(cell, jupyter.Code(code, output, execution_count=i+1).to_cell())

    def test_notebook(self):
        for cells,nb in notebooks:
            with self.subTest(cells):
                self.assertEqual(nb, jupyter.to_notebook(cells))

class TestMarkdown(unittest.TestCase):
    maxDiff = None

    def test_markdown(self):
        for md,expected in md_markdown:
            with self.subTest(md):
                self.assertEqual(expected, jupyter.Markdown(md).to_markdown())

    def test_code(self):
        for i,(code,output,expected) in enumerate(md_code):
            with self.subTest(code):
                self.assertEqual(expected, jupyter.Code(code, output, execution_count=i+1).to_markdown())
