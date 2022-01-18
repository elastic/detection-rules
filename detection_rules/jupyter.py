# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Helpers to generate Jupyter Notebooks."""

import os
import random
import string
import json
import uuid
import textwrap
import nbformat as nbf
from functools import wraps
from pathlib import Path

from . import utils

__all__ = (
    "Code",
    "Markdown",
)

random = random.Random()

github_user = "elastic"
github_repo = "detection-rules"
github_branch = "main"

def to_notebook(cells):
    metadata = {
        "language_info": {
            "file_extension": ".py",
            "mimetype": "text/x-python",
            "name": "python",
        }
    }
    nb = nbf.v4.new_notebook(metadata=metadata)
    nb.cells = [cell.to_cell() for cell in cells]
    return nb

def to_markdown(cells):
    text = "".join(line for cell in cells for line in cell.to_markdown() + ["\n\n"])
    while len(text) > 1 and text[-2:] == "\n\n":
        text = text[:-1]
    return text

def _get_nb_badges(filename):
    _nbviewer_badge_url = "https://raw.githubusercontent.com/jupyter/design/master/logos/Badges/nbviewer_badge.svg"
    _nbviewer_base_url = "https://nbviewer.jupyter.org/github"
    _binder_badge_url = "https://mybinder.org/badge_logo.svg"
    _binder_base_url = "https://mybinder.org/v2/gh"
    path = Path(filename).relative_to(utils.ROOT_DIR)

    if not github_user or not github_repo or not github_branch:
        return []

    return [Markdown(f"""
        [![nbviewer]({_nbviewer_badge_url})]({_nbviewer_base_url}/{github_user}/{github_repo}/blob/{github_branch}/{path})
        [![Binder]({_binder_badge_url})]({_binder_base_url}/{github_user}/{github_repo}/{github_branch}?labpath={path})
    """)]

def to_file(filename, cells):
    ext = os.path.splitext(filename)[1][1:]
    if ext == "ipynb":
        nb = to_notebook(_get_nb_badges(filename) + cells)
        nbf.write(nb, filename)
    elif ext == "md":
        md = to_markdown(cells)
        with open(filename, "w") as f:
            f.write(md)
    else:
        raise ValueError(f"unknown extension: {ext}")

def to_multiline(lines):
    if type(lines) == str:
        lines = [line for line in textwrap.dedent(lines).split("\n")]
    lines = [f"{line}\n" for line in lines]
    while lines and lines[0] == "\n":
        lines = lines[1:]
    while lines and lines[-1] == "\n":
        lines = lines[:-1]
    if lines and lines[-1] and lines[-1][-1] == "\n":
        lines[-1] = lines[-1][:-1]
    return lines

def _rewrite_id(cell):
    cell.id = uuid.UUID(int=random.getrandbits(128)).hex[:8]
    return cell

class Markdown:
    def __init__(self, text):
        self.text = text

    def to_cell(self):
        markup_args = {
            "source": to_multiline(self.text),
        }
        return _rewrite_id(nbf.v4.new_markdown_cell(**markup_args))

    def to_markdown(self):
        return to_multiline(self.text)

class Code:
    def __init__(self, code, output=None, output_type="execute_result", execution_count=None):
        self.code = code
        self.output = output
        self.output_type = output_type
        self.execution_count = execution_count

    def to_cell(self):
        code_args = {
            "source": to_multiline(self.code),
            "execution_count": self.execution_count,
        }
        cell = _rewrite_id(nbf.v4.new_code_cell(**code_args))

        if self.output is not None:
            output_args = {}
            if self.output_type == "execute_result":
                output_args = {
                    "execution_count": self.execution_count,
                    "data": {
                        "text/plain": to_multiline(self.output or []),
                    },
                }
            elif self.output_type == "stream":
                output_args = {
                    "name": "stdout",
                    "text": to_multiline(self.output or []),
                }
            else:
                raise NotImplementedError(f"Unknown output_type: {self.output_type}")
            cell.outputs.append(nbf.v4.new_output(self.output_type, **output_args))

        return cell

    def to_markdown(self):
        code = to_multiline(self.code)
        if code:
            code[-1] += "\n"
        lines = ["```python\n"] + code + ["```\n\n"]
        output = to_multiline(self.output or [])
        if output:
            output[-1] += "\n"
            lines += ["```python\n"] + output + ["```\n\n"]
        return lines

_markdown_punctuation = string.punctuation.translate(str.maketrans("", "", "-_"))
_markdown_anchor_trans = str.maketrans(" ", "-", _markdown_punctuation)
def _toc_entry(title, toc_style):
    indent = "   " * max(0, title.count("#") - 1)
    title = title.replace("#", "").strip()
    link = title.replace(" ", "-")
    if toc_style == "md":
        link = title.lower().translate(_markdown_anchor_trans)
    elif toc_style == "ipynb":
        pass
    else:
        raise ValueError(f"unknown toc style: {toc_style}")
    return f"{indent}1. [{title}](#{link})"

class Notebook:
    def __init__(self):
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

    def save(self, filename):
        toc_style = os.path.splitext(filename)[1][1:]
        toc = []
        cells = []
        for chap_title,chap_cells in self.chapters:
            if chap_title and chap_cells:
                toc.append(_toc_entry(chap_title, toc_style))
                cells.append(Markdown(f"{chap_title}"))
            cells += [cell for cell in chap_cells if cell]
        if toc:
            toc = [Markdown(["## Table of contents"] + toc)]
        to_file(filename, self.cells + toc + cells)
