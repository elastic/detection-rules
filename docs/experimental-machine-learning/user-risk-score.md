**The setup instructions in this document have been deprecated. Please follow the steps outlined [here](https://www.elastic.co/guide/en/security/current/user-risk-score.html), to enable User Risk Score in your environment.**
# User Risk Score

The User Risk Score feature highlights risky usernames from within your environment. It utilizes a transform with a scripted metric aggregation to calculate user risk scores based on alerts that were generated within the past three months. The transform runs hourly to update the score as new alerts are generated. Each alert's contribution to the user risk score is based on the alert's risk score (`signal.rule.risk_score`). The risk score is calculated using a weighted sum where rules with higher time-corrected risk scores also have higher weights. Each risk score is normalized to a scale of 0 to 100.

User Risk Score is an experimental feature that assigns risk scores to usernames in a given Kibana space. Risk scores are calculated for each username by utilizing transforms on the alerting indices. The transform updates the score as new alerts are generated. The User Risk Score [package](https://github.com/elastic/detection-rules/releases/tag/ML-UserRiskScore-20220628-1) contains all of the required artifacts for setup. The User Risk Score feature provides Lens dashboards for viewing summary and detailed username risk score information. The detail view dashboard - Drilldown of User Risk Score - presents detail on why a username has been given a high risk score. In addition, user risk scores are presented in the detailed view for a username in the Elastic Security App.


### On Usernames and Risk Scores

 Many alerts contain usernames which were present in the original log or event documents that alert rules, or anomaly rules, matched. These are discrete usernames, not (yet) pointers to a user *entity*. In most environments, each human user has multiple usernames across the various applications and systems they use. In order to investigate a user, it may be necessary to add each of their usernames to the list of usernames being used to filter the output of the detail dashboard.

In some cases, there are certain usernames that are not readily individuated. The Local System, or SYSTEM account, under Windows, for example, has the same name and the same SID (security identifier) on every Windows host. In order to individuate a particular Local System user account, it is necessary to add its hostname as a filter. The user risk score detail dashboard contains tables of alerts by hostname, in addition to username, in order to help identify the hostname(s) associated with a local user that has been given a risk score.

## Setup Instructions

 1. [Obtain artifacts](#obtain-artifacts)
 2. [Upload scripts](#upload-scripts)
 3. [Upload ingest pipeline](#upload-ingest-pipeline)
 4. [Upload and start the `pivot` transform](#upload-start-pivot)
 5. [Create the User Risk Score index](#user-risk-index)
 6. [Upload and start the `latest` transform](#upload-start-latest)
 7. [Import dashboards](#import-dashboards)
 8. [(Optional) Enable Kibana features](#enable-kibana)

<h3 id="modify-artifacts">1. Obtain artifacts</h3>

The User Risk Score functionality is space aware for privacy. Downloaded artifacts must be modified with the desired space before they can be used.

 - Download the release bundle from [here](https://github.com/elastic/detection-rules/releases/tag/ML-UserRiskScore-20220628-1). The User Risk Score releases can be identified by the tag `ML-UserRiskScore-YYYYMMDD-N`. Check the release description to make sure it is compatible with the Elastic Stack version you are running.
 - Unzip the contents of `ML-UserRiskScore-YYYYMMDD-N.zip`.
 - Run `ml_userriskscore_generate_scripts.py` script in the unzipped directory with your Kibana space as the argument.
<div style="margin-left: 40px">   
<i>Example of modifying artifacts for the default space</i>
   <pre style="margin-top:-2px"><code>python ml_userriskscore_generate_scripts.py --space default
</code></pre></div>

 - Find a new folder named after your space in the unzipped directory. **You will be using the scripts within this directory for the next steps.**

<h3 id="upload-scripts">2. Upload scripts</h3>

- Navigate to `Management / Dev Tools` in Kibana.
- Upload the contents of `ml_userriskscore_levels_script.json`, `ml_userriskscore_map_script.json`, `ml_userriskscore_reduce_script.json` using the Script API with the following syntax.
- Ensure that your space name (such as `default`) replaces `<your-space-name>` in the script names below.

<div style="margin-left: 40px">   
<i>uploading scripts</i>
   <pre style="margin-top:-2px"><code>
PUT _scripts/ml_userriskscore_levels_script_&lt;your-space-name&gt;
{contents of ml_userriskscore_levels_script.json file}
</code></pre></div>

<div style="margin-left: 40px">
   <pre><code>
PUT _scripts/ml_userriskscore_map_script_&lt;your-space-name&gt;
{contents of ml_userriskscore_map_script.json file}
</code></pre></div>

<div style="margin-left: 40px">
   <pre><code>
PUT _scripts/ml_userriskscore_reduce_script_&lt;your-space-name&gt;
{contents of ml_userriskscore_reduce_script.json file}
</code></pre></div>


<h3 id="upload-ingest-pipeline">3. Upload ingest pipeline</h3>

- Upload the contents of `ml_userriskscore_ingest_pipeline.json` using the Ingest API with the following syntax.
- Ensure that your space name (such as `default`) replaces `<your-space-name>` below.

<div style="margin-left: 40px">   
<i>uploading ingest pipeline</i>
   <pre style="margin-top:-2px"><code>PUT _ingest/pipeline/ml_userriskscore_ingest_pipeline_&lt;your-space-name&gt;
{contents of ml_userriskscore_ingest_pipeline.json file}
</code></pre></div>



<h3 id="upload-start-pivot">4. Upload and start the <code>pivot</code> transform</h3>

This transform calculates the risk level every hour for each username in the Kibana space specified.

- Upload the contents of `ml_userriskscore_pivot_transform.json` using the Transform API with the following syntax.
- Ensure that your space name (such as `default`) replaces `<your-space-name>` below.

<div style="margin-left: 40px">   
<i>uploading pivot transform</i>
   <pre style="margin-top:-2px"><code>PUT _transform/ml_userriskscore_pivot_transform_&lt;your-space-name&gt;
{contents of ml_userriskscore_pivot_transform.json file}
</code></pre></div>

- Navigate to `Transforms` under `Management / Stack Management` in Kibana. Find the transform with the ID `ml_userriskscore_pivot_transform_<your-space-name>`. Open the `Actions` menu on the right side of the row, then click `Start`.
- Confirm the transform is working as expected by navigating to `Management / Dev Tools` and ensuring the target index exists.

<div style="margin-left: 40px">   
<i>sample test query</i>
   <pre style="margin-top:-2px"><code>GET ml_user_risk_score_&lt;your-space-name&gt;/_search
</code></pre></div>

<h3 id="user-risk-index">5. Create the User Risk Score index</h3>

- Navigate to `Management / Dev Tools` in Kibana.
- Create the User Risk Score index (`ml_user_risk_score_latest_<your-space-name>`) with the following mappings.
- Ensure that your space name (such as `default`) replaces `<your-space-name>` below.

<div style="margin-left: 40px">   
<i>creating the User Risk Score index</i>
   <pre style="margin-top:-2px"><code>PUT ml_user_risk_score_latest_&lt;your-space-name&gt;
{
  "mappings":{
    "properties":{
      "user.name":{
        "type":"keyword"
      }
    }
  }
}
</code></pre></div>

<h3 id="upload-start-latest">6. Upload and start the <code>latest</code> transform</h3>

This transform recurrently calculates risk levels for all usernames in the Kibana space specified.

- Upload the contents of `ml_userriskscore_latest_transform.json` using the Transform API with the following syntax.
- Ensure that your space name (such as `default`) replaces `<your-space-name>` below.

<div style="margin-left: 40px">   
<i>uploading latest transform</i>
   <pre style="margin-top:-2px"><code>PUT _transform/ml_userriskscore_latest_transform_&lt;your-space-name&gt;
{contents of ml_userriskscore_latest_transform.json file}
</code></pre></div>

- Navigate to `Transforms` under `Management / Stack Management` in Kibana. Find the transform with the ID `ml_userriskscore_latest_transform_<your-space-name>`. Open the `Actions` menu on the right side of the row, and click `Start`.
- Confirm the transform is working as expected by navigating to `Management / Dev Tools` and ensuring the target index exists. You should see documents starting to appear in the index if there is ongoing alerting activity associated with usernames.

<div style="margin-left: 40px">   
<i>sample test query</i>
   <pre style="margin-top:-2px"><code>GET ml_user_risk_score_latest_&lt;your-space-name&gt;/_search
</code></pre></div>

<h3 id="import-dashboards">7. Import dashboards</h3>

- Navigate to `Management / Stack Management / Kibana / Saved Objects` in Kibana.
- Click on `Import` and import the `ml_userriskscore_dashboards.ndjson` file.
- Navigate to `Analytics / Dashboard`.
- Confirm you can see a dashboard named `Current Risk Scores for Users`, which displays the current list (Top 20) of  usernames for which a risk score has been computed.
- Confirm you can see a dashboard named `Drilldown of User Risk Score`, which allows you to further drill down into details of the risk associated with a particular username of interest.

<h3 id="enable-kibana">8. Enable Kibana features</h3>

To enable the Kibana features for User Risk Score, you will first need to add the following configuration to `kibana.yml`.

```
xpack.securitySolution.enableExperimental: ['riskyUsersEnabled']
```
This can be added by editing the kibana.yml file, on a Kibana server instance, or by modifying a Kibana server configuration, in an Elastic Cloud deployment, using the steps documented here:

https://www.elastic.co/guide/en/cloud-enterprise/current/ece-manage-kibana-settings.html

Once you have modified the `kibana.yml` file, you will find User Risk Scoring features in the "User Risk" tab in the detail view for a username. The detail view is reached by clicking a username in the Users page in the Security Solution:

<hr/>
