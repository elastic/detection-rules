# Host Risk Score- What is it?

The Host Risk Score package consists of all the artifacts required to stand up the host risk scoring framework in your environment. This framework leverages transforms and visualizations in Kibana to identify the most suspicious hosts in your environment, based on alert activity on the hosts. 
To deploy this framework in your environment, follow the steps outlined below.

# Detailed steps

#### 1. Unzip the release bundle

#### 2. Navigate to the Dev Tools console in Kibana

#### 3. Uploading required scripts

Upload the script in `ml_hostriskscore_levels_script.json` using the following API call:


```
PUT _scripts/ml_hostriskscore_levels_script
```

#### 4. Upload required ingest pipelines

Upload the ingest pipeline in `ml_hostriskscore_ingest_pipeline.json` using the following API call:


```
PUT _ingest/pipeline/ml_hostriskscore_ingest_pipeline
```

#### 5. Upload and start the `pivot` transform

Upload the `pivot` transform in `ml_hostriskscore_pivot_transform.json` using the following API call. This transform calculates the risk level per hour for each host in your environment:


```
PUT _transform/ml_hostriskscore_pivot_transform
```

* Navigate to `Transforms` under `Management` -> `Stack Management`. For the transform with the ID `ml_hostriskscore_pivot_transform`, under `Actions`, click `Start`. 
* Verify that the Transform started as expected by ensuring that documents are appearing in the destination index of the Transform, eg: using the Search/Count APIs:


```
GET ml_host_risk_score/_search (or _count)
```

#### 6. Create the `ml_host_risk_score_latest` index with appropriate mappings


```
PUT ml_host_risk_score_latest
{
    "mappings" : {
            "properties" : {
                "host.name" : { "type" : "keyword" }
            }
        }
}
```

#### 7. Upload the `latest` transform

Upload the `latest` transform in `ml_hostriskscore_latest_transform.json` using the following API call. This transform gets the most current risk levels for all the hosts in your environment:


```
PUT _transform/ml_hostriskscore_latest_transform
```

* Navigate to `Transforms` under `Management` -> `Stack Management`. For the transform with the ID `ml_hostriskscore_latest_transform`, under `Actions`, click `Start`. 
* Verify that the Transform started as expected by ensuring that documents are appearing in the destination index of the Transform, eg: using the Search/Count APIs:


```
GET ml_host_risk_score_latest/_search (or _count)
```

#### 8. Import the dashboards

* Navigate to `Management` -> `Stack Management` -> `Kibana` -> `Saved Objects`
* Click on `Import` and import the `ml_hostriskscore_dashboards.ndjson` file
* Navigate to `Analytics` -> `Dashboard`. You should see two dashboards- `Current Risky Hosts`, which displays the current list (Top 20) of suspicious hosts in your environment, and `Host Risk Drilldown`, which allows you to further drill down into details of the risk associated with a particular host of interest.

# About hostnames and host IDs

The Host Risk Score app currently uses host names (`host.name`), not the `host.id` field, for both searching and displaying hosts. There may be some edge cases where hosts use the same name. Physical Windows clients - desktops and laptops - in an Active Directory forest, are unlikely to have name collisions, as their computer accounts and distinguished names should be unique. Non-domain member servers, desktops and laptops, in a Windows workgroup, may occasionally have name collisions. Macs are often not managed by a directory service and may have name collisions. Virtual servers, that are created from templates or cloning processes may have hostname collisions.
