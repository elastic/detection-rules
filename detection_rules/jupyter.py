# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Helpers to generate Jupyter Notebooks."""

import sys
import random
import string
import json
import uuid
import textwrap
import nbformat as nbf
from functools import wraps

__all__ = (
    "Code",
    "Markdown",
    "to_file",
)

random = random.Random()

def to_notebook(cells):
    metadata = {
        "language_info": {
            "file_extension": ".py",
            "mimetype": "text/x-python",
            "name": "python",
            "version": ".".join(str(v) for v in sys.version_info[:3]),
        }
    }
    nb = nbf.v4.new_notebook(metadata=metadata)
    nb.cells = cells
    return nb

def to_file(fp, cells):
    nb = to_notebook(cells)
    nbf.write(nb, fp)

def to_multiline(lines):
    if type(lines) == str:
        lines = [line for line in textwrap.dedent(lines).split("\n")]
    lines = [f"{line}\n" for line in lines]
    while lines and lines[0] == "\n":
        lines = lines[1:]
    while lines and lines[-1] == "\n":
        lines = lines[:-1]
    if lines and lines[-1][-1] == "\n":
        lines[-1] = lines[-1][:-1]
    return lines

def _rewrite_id(cell):
    cell.id = uuid.UUID(int=random.getrandbits(128)).hex[:8]
    return cell

def Markdown(text):
    markup_args = {
        "source": to_multiline(text),
    }
    return _rewrite_id(nbf.v4.new_markdown_cell(**markup_args))

def Code(code, output=None, output_type="execute_result", execution_count=None):
    code_args = {
        "source": to_multiline(code),
        "execution_count": execution_count,
    }
    cell = _rewrite_id(nbf.v4.new_code_cell(**code_args))

    if output is not None:
        output_args = {}
        if output_type == "execute_result":
            output_args = {
                "execution_count": execution_count,
                "data": {
                    "text/plain": to_multiline(output or []),
                },
            }
        elif output_type == "stream":
            output_args = {
                "name": "stdout",
                "text": to_multiline(output or []),
            }
        else:
            raise NotImplementedError(f"Unknown output_type: {output_type}")
        cell.outputs.append(nbf.v4.new_output(output_type, **output_args))

    return cell

def _toc_entry(title):
    indent = " " * max(0, title.count("#") - 1)
    title = title.replace("#", "").strip()
    link = title.replace(' ', '-')
    return f"{indent}1. [{title}](#{link})"

class Notebook:
    def __init__(self, filename):
        self.filename = filename
        self.chapters = []
        self.cells = []

    class Chapter:
        def __init__(self, nb, title):
            self.cells = []
            nb.chapters.append((title, self.cells))

        def __call__(self, func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                kwargs["cells"] = self.cells
                return func(*args, **kwargs)
            return wrapper

        def __enter__(self):
            return self.cells

        def __exit__(self, *exc):
            return False

    def chapter(self, title):
        return Notebook.Chapter(self, title)

    def save(self):
        toc = ["## Table of contents"]
        cells = []
        for chap_title,chap_cells in self.chapters:
            if chap_title and chap_cells:
                toc.append(_toc_entry(chap_title))
                cells.append(Markdown(f"{chap_title}"))
            cells += chap_cells
        to_file(self.filename, self.cells + [Markdown(toc)] + cells)
