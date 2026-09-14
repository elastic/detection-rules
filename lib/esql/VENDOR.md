# Vendored python-esql

Snapshot of [elastic/python-esql](https://github.com/elastic/python-esql) `0.1.1` for detection-rules CI
until the package is published to PyPI (or the public cutover lands).

Refresh with:
```bash
rsync -a --delete --exclude '__pycache__' ../python-esql/esql/ lib/esql/esql/
# bump version in lib/esql/pyproject.toml to match
```

Do not hand-edit `esql/_antlr/` here — regenerate upstream and re-sync.
