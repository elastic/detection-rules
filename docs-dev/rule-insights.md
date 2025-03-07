# Insights and visualizations into rules and releases

## Indexing rules for visualizing in Kibana

There are several ways to import or index rules into elasticsearch.


### Indexing rules into Elasticsearch

The simplest way to index rules from the repo into elasticsearch is to run
`python -m detection-rules es index-rules`

This will index an enriched version of all rules included and sent to the index `rules-repo-<package-version>-<package_hash>`
- `package-version` is the version defined in `detection_rules/etc/packages.yaml`
- `package hash` is the sha256 hash of the consolidated rules:
   - sorted by name
   - flattened
   - sorted by key
   - base64 encoded


#### Detailed usage

```
Usage: detection_rules es index-rules [OPTIONS]

  Index rules based on KQL search results to an elasticsearch instance.

Options:
  -q, --query TEXT          Optional KQL query to limit to specific rules
  -f, --from-file FILENAME  Load a previously saved uploadable bulk file
  -s, --save_files          Optionally save the bulk request to a file
  -h, --help                Show this message and exit.
```

The query can be any valid kql to reduce the scope of included rules, such as

```
-q "tags:Windows and severity>50"
```


### Generating an index of the rules

Instead of automatically uploading the rules, you can save the files to do so locally and then import/upload

To do so, run `python -m detection-rules generate-rules-index`

This will generate 2 files under `enriched-rule-indexes/<hash-of-package>`:
* `enriched-rules-index-importable.ndjson`
   - this is a standard ndjson file of flattened enriched rules
* `enriched-rules-index-uploadable.ndjson`
   - this is an ndjson file in the format expected by the `bulk` [api](https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-bulk.html)
   - this can be loaded via dev tools or sent as data using curl or any other method that hits the elasticsearch bulk api


The rules are _enriched_ with several pieces of information and so are not identical
representations of the rules generated with `view-rule`, though the hashes of the rules are generated
before any enrichments are added.

#### Detailed usage

```
Usage: detection_rules generate-rules-index [OPTIONS]

  Generate enriched indexes of rules, based on a KQL search, for
  indexing/importing into elasticsearch/kibana.

Options:
  -q, --query TEXT  Optional KQL query to limit to specific rules
  --overwrite       Overwrite files in an existing folder
  -h, --help        Show this message and exit.
```

The query can be any valid kql to reduce the scope of included rules, such as

```
-q "tags:Windows and severity>50"
```

### Importing rules via Kibana

If you have [access](https://www.elastic.co/subscriptions) to machine learning, you can leverage the
[data-visualizer](https://www.elastic.co/guide/en/kibana/7.11/connect-to-elasticsearch.html#upload-data-kibana)
to import the rules via the [importable](#generating-an-index-of-the-rules) file.


### After the rules have been indexed

Once indexed, the rules will need to be added to a [kibana pattern](https://www.elastic.co/guide/en/kibana/7.11/index-patterns.html),
which will then make them searchable via discover or accessible in visualizations. Recommended index pattern is
`rules-*` or `rules-repo-*`


## For internal developers

Along with a series of other artifacts, these files are also generated at package creation, when running:
- `make release`
- `python -m detection-rules build-release`