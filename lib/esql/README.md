# Vendored python-esql (staging)

This directory vendors [elastic/python-esql](https://github.com/elastic/python-esql) so CI can
`pip install .[dev]` without a PyPI release.

* **Import:** `import esql`
* **Distribution name:** `python-esql`
* **Source of truth:** the private `python-esql` repo — re-sync after parser releases

When `python-esql` is published to PyPI, switch `detection-rules/pyproject.toml` to
`python-esql==X.Y.Z` and remove this tree (or keep it only for offline bootstrap).
