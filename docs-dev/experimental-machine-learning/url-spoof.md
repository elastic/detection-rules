# URL Spoofing Detection in the Elastic Stack 

With the introduction of the ***URL Spoofing*** framework, you can now detect and monitor potentially malicious URLs in your environment.

The framework leverages supervised machine learning methods, threat intelligence enrichments, and customized detection rules to create an alert when you interact with a potentially malicious URL.


*Note: In order to use these ML features, you must have a platinum or higher [subscription](https://www.elastic.co/subscriptions). This is an **experimental** detection capability that currently works with `Packetbeat` data or any index with a corresponding `url.full` field should you choose to use your own index.*  

## Detailed Workflow

### 1. Setup enrichment policy 

You will first need to setup an enrichment policy to indicate where to get enrichments from.

You can do this by running the following command in your *Dev Tools* console:

```
PUT /_enrich/policy/url_spoofing_enrichment_policy
{
  "match": {
    "indices": "filebeat-*",
    "query": {"match": {"event.dataset": "threatintel.abuseurl"}},
    "match_field": "threatintel.indicator.url.domain",
    "enrich_fields": ["threatintel.indicator.url.domain"]
  }
}
```
*Note: This enrichment pulls in threat intelligence data from `Filebeat`. You must have `Filebeat` data and a corresponding `filebeat-*` index/index pattern.*

### 2. Execute enrichment policy 
After setting up the enrichment policy, you will need to execute the policy in order to add enrichments to incoming documents.

Run the following command in your *Dev Tools* console:

```
PUT /_enrich/policy/url_spoofing_enrichment_policy/_execute
```
*Note: You will need to periodically re-execute the enrichment policy to ensure your documents are being enriched with the latest threat intelligence data. To do so, simply re-run the execution script from **Step 2**. Do **NOT** re-run the script from **Step 1**.*

### 3. Upload model and dependencies 

Run the following CLI command:
 ```
 python -m detection_rules es <args_or_config> experimental ml setup -t <release-tag>
 ```

If updating a new model, you should first uninstall any existing models using *remove-model*.


### 4. Update index pipeline configuration
You will need to update your index settings to point to the *URL Spoofing* pipeline.

You can do this by running the following command in your *Dev Tools* console:
```
PUT your-index-pattern/_settings
{
  "index": {
    "default_pipeline": ml_urlspoof_inference_pipeline
  }
}
```

Run the following command in your *Dev Tools* console to stop adding enrichments from the *URL Spoofing* framework to your documents:
```
PUT your-index-pattern/_settings
{
  "index": {
    "default_pipeline": null
  }
}
```
### 5. Refresh your indexes (Optional)

You can optionally choose to refresh your index mapping from within Kibana:

- Navigate to Stack Management > (Kibana) Index Patterns
- Select the appropriate indexes
- Click refresh field list


### 6. Upload detection rule(s)


You can upload the rules associated with the *URL Spoofing* framework using the instructions provided [here](https://github.com/elastic/detection-rules/blob/main/docs-dev/experimental-machine-learning/experimental-detections.md)


And that's it! You should now be alerted whenever you interact with a predicted malicious URL in your environment.








