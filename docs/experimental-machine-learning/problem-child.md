**The setup instructions in this document have been deprecated. Please follow the steps outlined in [this](https://www.elastic.co/security-labs/detecting-living-off-the-land-attacks-with-new-elastic-integration) blog to enable Living off the Land (LotL) detection in your environment.**
# ProblemChild in the Elastic Stack 

ProblemChild helps detect anomalous activity in Windows process events by:
1) Classifying events as malicious vs benign
2) Identifying anomalous events based on rare parent-child process relationships

An end-to-end blog on how to build the ProblemChild framework from scratch for your environment can be found [here](https://www.elastic.co/blog/problemchild-detecting-living-off-the-land-attacks).

You can also find some supplementary material for the blog and examples [here](https://github.com/elastic/examples/tree/master/Machine%20Learning/ProblemChild)

We also released a blog about getting started with ProblemChild using the CLI and Kibana:
* [ProblemChild Release Blog](link to blog)


*Note: in order to use these ML features, you must have a platinum or higher [subscription](https://www.elastic.co/subscriptions)*
*Note: the ML features are considered experimental in Kibana as well as this rules CLI*


## Detailed steps

#### 1. Upload and setup the model file and dependencies

Run `python -m detection_rules es <args_or_config> experimental ml setup -t <release-tag>`

*If updating a new model, you should first uninstall any existing models using `remove-model`*

You can also upload files locally using the `-d` option, so long as the naming convention of the files match the 
expected pattern for the filenames.

#### 2. Update index pipeline configuration

You will need to update your index (containing Windows process event data) settings to point to the ProblemChild enrichment pipeline.

You can do this by running the following command in your Dev Tools console:
```
PUT your-index-pattern/_settings
{
  "index": {
    "default_pipeline": "ML_ProblemChild_ingest_pipeline"
  }
}
```

If you wish to stop enriching your documents using ProblemChild, run the following command in your dev Tools console:
```
PUT your-index-pattern/_settings
{
  "index": {
    "default_pipeline": null
  }
}

```

#### 3. Refresh your indexes

You can optionally choose to refresh your index mapping from within Kibana:
* Navigate to `Stack Management > (Kibana) Index Patterns` 
* Select the appropriate indexes
* Click `refresh field list`

#### 4. Verify enrichment fields

Any documents corresponding to Windows process events should now be enriched with `problemchild.*`. By default, the enrichment pipeline also consists of a script processor for a blocklist, so you might also see the field `blocklist_label` appear in documents that match the blocklist.
