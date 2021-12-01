# Discovering beaconing activity in your environment

The Beaconing package consists of all the artifacts required to stand up a beaconing discovery framework in your environment. The framework can not only help threat hunters and analysts monitor network traffic for beaconing activity, but also provides useful indicators of compromise (IoCs) for them to start an investigation with. 
To deploy this framework in your environment, follow the steps outlined below.

# Detailed steps

#### 1. Unzip the release bundle

Navigate to the latest GitHub [release](https://github.com/elastic/detection-rules/releases), with the tag `ML-Beaconing-YYYMMDD-N`. From under `Assets`, download the zip file named `ML-Beaconing-YYYMMDD-N.zip` and unzip it. New releases may contain updated artifacts.

#### 2. Navigate to the Dev Tools console in Kibana

You will now upload all the required artifacts from the release package to Kibana.
#### 3. Uploading required scripts

Upload the contents of `ml_beaconing_init_script.json`, `ml_beaconing_map_script.json` and `ml_beaconing_reduce_script.json` as individual scripts, using the Script API.

Eg:

```
PUT _scripts/ml_beaconing_init_script
{content of the ml_beaconing_init_script.json file}
```

#### 4. Upload required ingest pipelines

Upload the ingest pipeline in `ml_beaconing_ingest_pipeline.json` using the following API call:


```
PUT _ingest/pipeline/ml_beaconing_ingest_pipeline
{content of the ml_beaconing_ingest_pipeline.json file}
```

#### 5. Upload and start the `pivot` transform

Upload the `pivot` transform in `ml_beaconing_pivot_transform.json` using the following API call. This transform runs hourly and flags beaconing activity seen in your environment, in the 6 hrs prior to runtime:


```
PUT _transform/ml_beaconing_pivot_transform
{content of the ml_beaconing_pivot_transform.json file}
```

* Navigate to `Transforms` under `Management` -> `Stack Management`. For the transform with the ID `ml_beaconing_pivot_transform`, under `Actions`, click `Start`. 
* Verify that the Transform started as expected by ensuring that documents are appearing in the destination index of the Transform, eg: using the Search/Count APIs:


```
GET ml_beaconing/_search (or _count)
```

#### 6. Import the dashboards

* Navigate to `Management` -> `Stack Management` -> `Kibana` -> `Saved Objects`
* Click on `Import` and import the `ml_beaconing_dashboards.ndjson` file. Choose the `Request Action on conflict` option if you don't want the import to overwrite existing objects, for example the `logs-*` index pattern. 
* Navigate to `Analytics` -> `Dashboard`. You should see three dashboards- `Beaconing Discovery`, which is the main dashboard to monitor beaconing activity, `Beaconing Drilldown` to drilldown into relevant event logs and some statistics related to the beaconing activity, and finally, `Hosts Affected Over Time By Process Name` to monitor the reach of beaconing processes across hosts in your environment, in the past two weeks.

# Note

Platinum and Enterprise customers can enable the anomaly detection job associated with this beaconing discovery framework. This job additionally allows users to find processes in their environment that don't normally beacon out. The job configuration and datafeed can be found in the latest experimental detections package, which is available as a GitHub release [here](https://github.com/elastic/detection-rules/releases), with the tag `ML-experimental-detections-YYYMMDD-N`.
