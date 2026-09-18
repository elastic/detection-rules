# Vendored esql-detection-rules-py

Snapshot of [elastic/esql-detection-rules-py](https://github.com/elastic/esql-detection-rules-py) for detection-rules CI
until the package is published to PyPI (or the public cutover lands).

Current staging snapshot: [`elastic/python-esql@cb62ec9`](https://github.com/elastic/python-esql/commit/cb62ec942577f9f63fcac91489cb18bfb462a900).

Refresh from the staging checkout (until the official repo cutover):
```bash
rsync -a --delete --exclude '__pycache__' ../python-esql/esql/ lib/esql/esql/
# bump version in lib/esql/pyproject.toml to match
```

Do not hand-edit `esql/_antlr/` here — regenerate upstream and re-sync.
