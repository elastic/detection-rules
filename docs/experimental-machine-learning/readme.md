# Experimental machine learning

This repo contains some additional information and files to use experimental[*](#what-does-experimental-mean-in-this-context) machine learning features and detections

## Features
* [DGA](DGA.md)
* [ProblemChild](problem_child.md)
* [experimental detections](experimental-detections.md)

## Releases

There are separate [releases](https://github.com/elastic/detection-rules/releases) for:
* DGA: `ML-DGA-*`
* problem child: `ML-ProblemChild-*`
* experimental detections: `ML-experimental-detections-*`


## CLI

Support commands can be found under `python -m detection_rules es <es args> experimental ml -h`

```console
Elasticsearch client:
Options:
  -et, --timeout INTEGER    Timeout for elasticsearch client
  -ep, --es-password TEXT
  -eu, --es-user TEXT
  --elasticsearch-url TEXT
  --cloud-id TEXT


* experimental commands are use at your own risk and may change without warning *

Usage: detection_rules es experimental ml [OPTIONS] COMMAND [ARGS]...

  Experimental machine learning commands.

Options:
  -h, --help  Show this message and exit.

Commands:
  check-files               Check ML model files on an elasticsearch...
  delete-job                Remove experimental ML jobs.
  remove-model              Remove ML model files.
  remove-scripts-pipelines  Remove ML scripts and pipeline files.
  setup                     Upload ML model and dependencies to enrich data.
  upload-job                Upload experimental ML jobs.
```

----

##### What does experimental mean in this context?

Experimental model bundles (models, scripts, and pipelines), rules, and jobs are components which are currently in 
development and so may not have completed the testing or scrutiny which full production detections are subjected to.

It may also make use of features which are not yet GA and so may be subject to change and are not covered by the support 
SLA of general release (GA) features. Some of these features may also never make it to GA.