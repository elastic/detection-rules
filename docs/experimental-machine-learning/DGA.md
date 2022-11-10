**The setup instructions in this document have been deprecated. Please follow the steps outlined in [this](https://www.elastic.co/security-labs/detect-domain-generation-algorithm-activity-with-new-Kibana-integration) blog to enable DGA detection in your environment.**
# Machine Learning on Domain Generation Algorithm (DGA)

To create and use supervised DGA ML models to enrich data within the stack, check out these Elastic blogs:
* Part 1: [Machine learning in cybersecurity: Training supervised models to detect DGA activity](https://www.elastic.co/blog/machine-learning-in-cybersecurity-training-supervised-models-to-detect-dga-activity)
* Part 2: [Machine learning in cybersecurity: Detecting DGA activity in network data](https://www.elastic.co/blog/machine-learning-in-cybersecurity-detecting-dga-activity-in-network-data)

You can also find some supplementary material and examples [here](https://github.com/elastic/examples/tree/master/Machine%20Learning/DGA%20Detection)

We also released a blog about getting started with DGA using the CLI and Kibana, which also includes a case study of the process applied to the 2020 [SolarWinds supply chain attack](https://www.elastic.co/blog/elastic-security-provides-free-and-open-protections-for-sunburst):
* [Combining supervised and unsupervised machine learning for DGA detection](https://www.elastic.co/blog/supervised-and-unsupervised-machine-learning-for-dga-detection)


For questions, please reach out to the ML team in the #machine-learning channel of the 
[Elastic community Slack workspace](https://www.elastic.co/blog/join-our-elastic-stack-workspace-on-slack)

The team can also be reached by using the `stack-machine-learning` tag in the [discuss forums](https://discuss.elastic.co/tags/c/elastic-stack/stack-machine-learning)

*Note: in order to use these ML features, you must have a platinum or higher [subscription](https://www.elastic.co/subscriptions)*
*Note: the ML features are considered experimental in Kibana as well as this rules CLI*


## Detailed steps

#### 1. Upload and setup the model file and dependencies

Run `python -m detection_rules es <args_or_config> experimental ml setup -t <release-tag>`

*If updating a new model, you should first uninstall any existing models using `remove-model`*

You can also upload files locally using the `-d` option, so long as the naming convention of the files match the 
expected pattern for the filenames.

#### 2. Update packetbeat configuration

You will need to update your packetbeat.yml config file to point to the enrichment pipeline

Under `Elasticsearch Output` add the following:

```yaml
output.elasticsearch:
  hosts: ["your-hostname:your-port"]
  pipeline: dns_enrich_pipeline
```

#### 3. Refresh your packetbeat index

You can optionally choose to refresh your packetbeat index mapping from within Kibana:
* Navigate to `Stack Management > (Kibana) Index Patterns` 
* Select the appropriate packetbeat index
* Click `refresh field list`

#### 4. Verify enrichment fields

Any packetbeat documents with the field `dns.question.registered_domain` should now be enriched with `ml_is_dga.*`
