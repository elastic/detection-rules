# ProblemChild in the Elastic Stack 

ProblemChild helps detect anomalous activity in Windows process events by:
1) Classifying events as malicious vs benign
2) Identifying anomalous events based on rare parent-child process relationships

An end-to-end blog to create and leverage ProblemChild to detect anomalous Windows process events can be found 
[here](https://www.elastic.co/blog/problemchild-detecting-living-off-the-land-attacks).

You can also find some supplementary material for the blog and examples [here](https://github.com/elastic/examples/tree/master/Machine%20Learning/ProblemChild)

We also released a blog on getting started with ProblemChild using the CLI and Kibana:
* [ProblemChild Release Blog](link to blog)


*Note: in order to use these ML features, you must have a platinum or higher [subscription](https://www.elastic.co/subscriptions)*
*Note: the ML features are considered experimental in Kibana as well as this rules CLI*


## Uploading a model and dependencies using the CLI

### Usage

```console
python -m detection_rules es experimental ml setup -h

Elasticsearch client:
Options:
  -et, --timeout INTEGER    Timeout for elasticsearch client
  -ep, --es-password TEXT
  -eu, --es-user TEXT
  --cloud-id TEXT
  --elasticsearch-url TEXT


* experimental commands are use at your own risk and may change without warning *

Usage: detection_rules es experimental ml setup [OPTIONS]

  Upload ML model and dependencies to enrich data.

Options:
  -t, --model-tag TEXT       Release tag for model files staged in detection-
                             rules (required to download files)
  -r, --repo TEXT            GitHub repository hosting the model file releases
                             (owner/repo)
  -d, --model-dir DIRECTORY  Directory containing local model files
  --overwrite                Overwrite all files if already in the stack
  -h, --help                 Show this message and exit.

```

### Detailed steps

#### 1. Upload and setup the model file and dependencies

Run `python -m detection_rules es <args_or_config> experimental ml setup -t <release-tag>`

*If updating a new model, you should first uninstall any existing models using `remove-model`*

You can also upload files locally using the `-d` option, so long as the naming convention of the files match the 
expected pattern for the filenames.

#### 2. 