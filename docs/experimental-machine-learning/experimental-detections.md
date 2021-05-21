# Experimental ML Jobs and Rules

Once data is being enriched, there are some rules and ML jobs which can leverage the enriched fields. 
The experimental rules and jobs will be staged separate from the model bundle under the [releases](https://github.com/elastic/detection-rules/releases) 
as `ML-experimental-detections-YYYMMDD-N`. 

These releases will be additive, in that rule updates will come out in new releases.

Note that if a rule is of `type = "machine_learning"`, then it may be dependent on a uploading and running a machine
learning job first. If this is the case, it will likely be annotated within the `note` field of the rule.

### Uploading rules

You can then individually upload these rules using the [kibana upload-rule](../CLI.md#uploading-rules-to-kibana) command

### Uploading ML Jobs

Unzip released jobs and then run `python -m detection_rules es <args> experimental ml upload-job <ml_job.json>`

To delete a job, run `python -m detection_rules es <args> experimental ml delete-job <job-name> <job-type>`

Take note of any errors as some jobs may have dependencies on each other which may require stopping and or removing
referenced jobs first.
