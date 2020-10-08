# Machine Learning on Domain Generation Algorithm (DGA)

Several blogs were put out on how you can create and leverage supervised DGA ML models to enrich data within the stack.
* Part 1: [Machine learning in cybersecurity: Training supervised models to detect DGA activity](https://www.elastic.co/blog/machine-learning-in-cybersecurity-training-supervised-models-to-detect-dga-activity)
* Part 2: [Machine learning in cybersecurity: Detecting DGA activity in network data](https://www.elastic.co/blog/machine-learning-in-cybersecurity-detecting-dga-activity-in-network-data)

You can also find some supplementary and examples [here](https://github.com/elastic/examples/tree/master/Machine%20Learning/DGA%20Detection)

For questions, please reach out to the ML team in the #machine-learning channel of the 
[Elastic public slack channel](https://www.elastic.co/blog/join-our-elastic-stack-workspace-on-slack)

They can also be reached by using the `stack-machine-learning` tag in the [discuss forums](https://discuss.elastic.co/tags/c/elastic-stack/stack-machine-learning)

## Releases

Models and dependencies will be [released](https://github.com/elastic/detection-rules/releases) as `*-ML-DGA-v0.1.0`

## Uploading a Model and dependencies using the CLI

### Simple Usage

Run `python -m detection_rules es <args_or_config> experimental setup-dga-model -t <release-tag>`

Any packetbeat documents with the field `dns.question.registered_domain` should now have the enriched data


### Details
```console
python -m detection_rules es experimental setup-dga-model -h

Elasticsearch client:
Options:
  -u, --elasticsearch-url TEXT
  --cloud-id TEXT
  -u, --user TEXT
  -p, --es-password TEXT
  -t, --timeout INTEGER         Elasticsearch client kwargs

Usage: detection_rules es experimental setup-dga-model [OPTIONS]

  Upload DGA model and enrich DNS data.

Options:
  -t, --model-tag TEXT       Release tag for model files staged in detection-
                             rules (required to download files)
  -d, --model-dir DIRECTORY  Directory containing local model files
  --overwrite                Overwrite all files if already in the stack
  -h, --help                 Show this message and exit.
```

If updating a new model, you should first uninstall any existing models using `remove-dga-model`

#### Local Files

You can also upload files locally using the `-d` option, so long as the naming convention matches the expected pattern 
for the filenames.

## Rules

There are several rules within the repo which leverage this enriched data. The easiest way to see these rules is to run
`python -m detection_rules rule-search "tags:ML-DGA"`

You can then individually upload these rules using the [kibana upload-rule](../CLI.md#uploading-rules-to-kibana) command