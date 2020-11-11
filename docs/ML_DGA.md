# Machine Learning on Domain Generation Algorithm (DGA)

Several blogs were put out on how you can create and leverage supervised DGA ML models to enrich data within the stack.
* Part 1: [Machine learning in cybersecurity: Training supervised models to detect DGA activity](https://www.elastic.co/blog/machine-learning-in-cybersecurity-training-supervised-models-to-detect-dga-activity)
* Part 2: [Machine learning in cybersecurity: Detecting DGA activity in network data](https://www.elastic.co/blog/machine-learning-in-cybersecurity-detecting-dga-activity-in-network-data)

You can also find some supplementary and examples [here](https://github.com/elastic/examples/tree/master/Machine%20Learning/DGA%20Detection)

For questions, please reach out to the ML team in the #machine-learning channel of the 
[Elastic public slack channel](https://www.elastic.co/blog/join-our-elastic-stack-workspace-on-slack)

They can also be reached by using the `stack-machine-learning` tag in the [discuss forums](https://discuss.elastic.co/tags/c/elastic-stack/stack-machine-learning)

*Note: in order to use these ML features, you must have a platinum or higher [subscription](https://www.elastic.co/subscriptions)*

## Releases

Models and dependencies will be [released](https://github.com/elastic/detection-rules/releases) as `ML-DGA-YYYMMDD-N`.
This tag name is what will need to be passed to the CLI command.

## Uploading a model and dependencies using the CLI

### Usage

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

### Detailed steps

#### 1. Upload and setup the model file and dependencies

Run `python -m detection_rules es <args_or_config> experimental setup-dga-model -t <release-tag>`

*If updating a new model, you should first uninstall any existing models using `remove-dga-model`*

You can also upload files locally using the `-d` option, so long as the naming convention of the files match the 
expected pattern for the filenames.

#### 2. Update packetbeat configuration

You will need to update your packebeat.yml config file to point to the enrichment pipeline

Under `Elasticsearch Output` add the following:

```yaml
output.elasticsearch:
  hosts: ["your-hostname:your-port"]
  pipeline: dns_enrich_pipeline
```

#### 3. Refresh your packetbeat index

You can optionally choose to refresh your packetbeat index mapping within Kibana:
* navigate to `Stack Management > (Kibana) Index Patterns` 
* select the applicable packetbeat index
* click `refresh field list`

#### 4. Verify enrichment fields

Any packetbeat documents with the field `dns.question.registered_domain` should now have the enriched data:
`ml_is_dga.*`


## Experimental DGA ML Jobs and Rules

Once packetbeat data is being enriched, there are some rules and ML jobs which can leverage the enriched fields. 
The experimental rules and jobs will be staged separate from the model bundle under the [releases](https://github.com/elastic/detection-rules/releases) 
as `ML-experimental-detections-YYYMMDD-N`.

Note that if a rule is of `type = "machine_learning"`, then it may be dependent on a uploading and running a machine
learning job first. If this is the case, it will likely be annotated within the `note` field of the rule.

#### Uploading rules

You can then individually upload these rules using the [kibana upload-rule](../CLI.md#uploading-rules-to-kibana) command

#### Uploading ML Jobs

Unzip released jobs and then run `python -m detection_rules es <args> experimental upload-ml-job <ml_job.json>`

To delete a job, run `python -m detection_rules es <args> experimental delete-ml-job <job-name> <job-type>`

Take note of any errors as some jobs may have dependencies on each other which may require stopping and or removing
referenced jobs first.


## For Maintainers

### Validating release bundles and releasing

Release assets are expected to be in certain formats with specific naming patterns and json structures.

#### Filename patterns

DGA model file naming convention should match the following patterns

```json
{
  "model":                                "dga_*_model.json",
  "dga_ngrams_create":                    "dga_*_ngrams_create.json",
  "dga_ngrams_transform_delete":          "dga_*_ngrams_transform_delete.json",
  "dns_enrich_pipeline":                  "dga_*_ingest_pipeline1.json",
  "dns_dga_inference_enrich_pipeline":    "dga_*_ingest_pipeline2.json"
}
```

Experimental detections do not have to match a specific naming pattern but should be in the following file formats:
* rules: toml
* jobs: json

#### Uniqueness

The model file name and hash should be unique or else it will raise a warning in validation. This is important to allow 
distinction and ascertain information about a bundle by consulting the manifest, based on a unique name

Release zipped assets, name, and tag name all share the same name. These should follow the following format:
* Model releases: `ML-DGA-20\d\d[0-1]\d[0-3]\d-\d`
* Detection releases: `ML-experimental-detections-20\d\d[0-1]\d[0-3]\d-\d`

the trailing digit should be incremented for each release 

Rule and Job names should also be unique

#### Rule and job structure

Rules files are only check if they are valid toml, nothing more. Consult existing production rules and schemas for API 
expectations

Job files are checked if they are valid toml and contain the following top level fields:
* name - job name
* type - job type
* body - the meat of the job. The contents are not validated

#### Validation

All of these checks are automated and can be called with:
`python -m detection-rules dev gh-release validate-ml-dga-asset` - for model bundles
`python -m detection-rules dev gh-release validate-ml-detections-asset` for rule/job bundles

Pay attention to the output to determine any necessary changes. This may not be all inclusive and actual testing on a 
live stack should always occur even with passing validation before saving to a GitHub release

#### Releasing

A release can be done via the cli using `python -m detection-rules dev gh-release create-ml`

* you can only use a github token
* the base directory name and release name must match
* you must have write permissions to the repo to create a release
* validation also occurs on this, with a prompt to proceed
* upon completion, a manifest is saved in [etc/release_manifests](/etc/release_manifests)

To test, you can fork the repo and use `--repo <you-fork` to validate a release is working as expected