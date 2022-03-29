# Experimental ML Jobs and Rules

The ingest pipeline enriches process events by adding additional fields, which are used to power several rules. 
The experimental rules and jobs are staged separately from the model bundles under [releases](https://github.com/elastic/detection-rules/releases), with the tag `ML-experimental-detections-YYYMMDD-N`. New releases with this tag may contain either updates to existing rules or new experimental detections. 

Note that if a rule is of `type = "machine_learning"`, then it may be dependent on uploading and running a machine
learning job first. If this is the case, it will likely be annotated within the `note` field of the rule.

### Uploading rules

Unzip the release bundle and upload these rules individually.

Rules are now stored in ndjson format and can be imported into Kibana via the security app detections page.

Earlier releases stored the rules in toml format. These can be uploaded using the 
[7.12 branch](https://github.com/elastic/detection-rules/tree/7.12) CLI using the 
[kibana upload-rule](../../CLI.md#uploading-rules-to-kibana) command

### Uploading ML Jobs and Datafeeds

Unzip the release bundle and then run `python -m detection_rules es <args> experimental ml upload-job <ml_job.json>`

To delete a job/datafeed, run `python -m detection_rules es <args> experimental ml delete-job <job-name> <job-type>`

The CLI automatically identifies whether the provided input file is an ML job or datafeed.

Take note of any errors as the jobs and datafeeds may have dependencies on each other which may require stopping and/or removing
referenced jobs/datafeeds first.
