
# Experimental machine learning

This repo contains some additional information and files to use experimental[*](#what-does-experimental-mean-in-this-context) machine learning features and detections

## Features
* [DGA](DGA.md)
* [ProblemChild](problem-child.md)
* [HostRiskScore](host-risk-score.md)
* [URLSpoof](url-spoof.md)
* [UserRiskScore](user-risk-score.md)
* [experimental detections](experimental-detections.md)

## Releases

There are separate [releases](https://github.com/elastic/detection-rules/releases) for:
* DGA: `ML-DGA-*`
* ProblemChild: `ML-ProblemChild-*`
* Host Risk Score: `ML-HostRiskScore-*`
* URL Spoof: `ML-URLSpoof-*`
* experimental detections: `ML-experimental-detections-*`

Releases will use the tag `ML-TYPE-YYYMMDD-N`, which will be needed for uploading the model using the CLI.


##### What does experimental mean in this context?

Experimental model bundles (models, scripts, and pipelines), rules, and jobs are components which are currently in 
development and so may not have completed the testing or scrutiny which full production detections are subjected to.

It may also make use of features which are not yet GA and so may be subject to change and are not covered by the support 
SLA of general release (GA) features. Some of these features may also never make it to GA.