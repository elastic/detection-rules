# Identifying beaconing activity in your environment

The Network Beaconing package consists of all the artifacts required to stand up a framework to identify beaconing activity in your environment. The framework can not only help threat hunters and analysts monitor network traffic for beaconing activity, but also provides useful indicators of compromise (IoCs) for them to start an investigation with. 
To deploy this framework in your environment, follow the steps outlined below.

# Detailed steps

#### 1. Obtain artifacts

The Network Beaconing functionality is space aware for privacy. Downloaded artifacts must be modified with the desired space before they can be used.

 - Download the release bundle from [here](https://github.com/elastic/detection-rules/releases). The Network Beaconing releases can be identified by the tag `ML-Beaconing-YYYMMDD-N`. Check the release description to make sure it is compatible with the Elastic Stack version you are running. New releases may contain updated artifacts.
 - Unzip the contents of `ML-Beaconing-YYYMMDD-N`.
 - Run `ml_beaconing_generate_scripts.py` script in the unzipped directory with your Kibana space as the argument.
<div style="margin-left: 40px">   
<i>Example of modifying artifacts for the default space</i>
   <pre style="margin-top:-2px"><code>python ml_beaconing_generate_scripts.py --space default
</code></pre></div>

 - Find a new folder named after your space in the unzipped directory. **You will be using the scripts within this directory for the next steps.**

#### 2. Uploading scripts

- Navigate to `Management / Dev Tools` in Kibana.
- Upload the contents of `ml_beaconing_init_script.json`, `ml_beaconing_map_script.json` and `ml_beaconing_reduce_script.json` using the Script API with the following syntax.

<div style="margin-left: 40px">   
<i>uploading scripts</i>
   <pre style="margin-top:-2px"><code>
PUT _scripts/ml_beaconing_init_script
{contents of ml_beaconing_init_script.json file}
</code></pre></div>

<div style="margin-left: 40px">
   <pre><code>
PUT _scripts/ml_beaconing_map_script
{contents of ml_beaconing_map_script.json file}
</code></pre></div>

<div style="margin-left: 40px">
   <pre><code>
PUT _scripts/ml_beaconing_reduce_script
{contents of ml_beaconing_reduce_script.json file}
</code></pre></div>

#### 3. Upload ingest pipeline

Upload the contents of the `ml_beaconing_ingest_pipeline.json` ingest pipeline using the Ingest API with the following syntax.

<div style="margin-left: 40px">   
<i>uploading ingest pipeline</i>
   <pre style="margin-top:-2px"><code>PUT _ingest/pipeline/ml_beaconing_ingest_pipeline
{contents of ml_beaconing_ingest_pipeline.json file}
</code></pre></div>

#### 5. Upload and start the `pivot` transform

- Upload the contents of `ml_beaconing_pivot_transform.json` using the Transform API with the following syntax. This transform runs hourly and flags beaconing activity seen in your environment, in the 6 hrs prior to runtime:

<div style="margin-left: 40px">   
<i>uploading pivot transform</i>
   <pre style="margin-top:-2px"><code>PUT _transform/ml_beaconing_pivot_transform
{contents of ml_beaconing_pivot_transform.json file}
</code></pre></div>

- Navigate to `Transforms` under `Management` -> `Stack Management`. For the transform with the ID `ml_beaconing_pivot_transform`, under `Actions`, click `Start`. 
- Verify that the Transform started as expected by ensuring that documents are appearing in the destination index of the Transform, eg: using the Search/Count APIs:

<div style="margin-left: 40px">   
<i>sample test query</i>
   <pre style="margin-top:-2px"><code>GET ml_beaconing_&lt;your-space-name&gt;/_search
</code></pre></div>

#### 6. Import the dashboards

- Navigate to `Management` -> `Stack Management` -> `Kibana` -> `Saved Objects`
- Click on `Import` and import the `ml_beaconing_dashboards.ndjson` file. Choose the `Request Action on conflict` option if you don't want the import to overwrite existing objects, for example the `logs-*` index pattern. 
- Navigate to `Analytics` -> `Dashboard`. You should see three dashboards- `Network Beaconing`, which is the main dashboard to monitor beaconing activity, `Beaconing Drilldown` to drilldown into relevant event logs and some statistics related to the beaconing activity, and finally, `Hosts Affected Over Time By Process Name` to monitor the reach of beaconing processes across hosts in your environment, in the past two weeks.

# Note

Platinum and Enterprise customers can enable the anomaly detection job associated with this beaconing identification framework. This job additionally allows users to find processes in their environment that don't normally beacon out. The job configuration and datafeed can be found in the latest experimental detections package, which is available as a GitHub release [here](https://github.com/elastic/detection-rules/releases), with the tag `ML-experimental-detections-YYYMMDD-N`.
