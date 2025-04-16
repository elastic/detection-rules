import os
import json
import sys
from elasticsearch import Elasticsearch, helpers
from urllib.parse import urlparse

# Configuration variables (modify these as needed)
ELASTICSEARCH_URL = "http://localhost:9200"  # Your Elasticsearch URL
ELASTICSEARCH_USERNAME = "elastic"           # Your Elasticsearch username
ELASTICSEARCH_PASSWORD = "changeme"          # Your Elasticsearch password
ELASTICSEARCH_INDEX = "threat-hunting-queries"             # Target index name
# Directory containing JSON files
DIRECTORY_PATH = "/Users/mark/dev/detection-rules/hunting"
MAPPING = {
    "mappings": {
        "properties": {
            "author": {
                "type": "keyword"
            },
            "description": {
                "type": "text",
                "fields": {
                    "keyword": {
                        "type": "keyword",
                        "ignore_above": 256
                    }
                }
            },
            "from": {
                "type": "keyword"
            },
            "index": {
                "type": "keyword"
            },
            "language": {
                "type": "keyword"
            },
            "license": {
                "type": "keyword"
            },
            "name": {
                "type": "text",
                "fields": {
                    "keyword": {
                        "type": "keyword",
                        "ignore_above": 256
                    }
                }
            },
            "note": {
                "type": "text"
            },
            "queries": {
                "properties": {
                    "query": {
                        "type": "text"
                    },
                    "indices": {
                        "type": "keyword"
                    }
                }
            },
            "references": {
                "type": "keyword"
            },
            "related_integrations": {
                "properties": {
                    "package": {
                        "type": "keyword"
                    },
                    "version": {
                        "type": "keyword"
                    }
                }
            },
            "required_fields": {
                "properties": {
                    "ecs": {
                        "type": "boolean"
                    },
                    "name": {
                        "type": "keyword"
                    },
                    "type": {
                        "type": "keyword"
                    }
                }
            },
            "risk_score": {
                "type": "integer"
            },
            "rule_id": {
                "type": "keyword"
            },
            "setup": {
                "type": "text"
            },
            "severity": {
                "type": "keyword"
            },
            "tags": {
                "type": "keyword"
            },
            "threat": {
                "properties": {
                    "framework": {
                        "type": "keyword"
                    },
                    "tactic": {
                        "properties": {
                            "id": {
                                "type": "keyword"
                            },
                            "name": {
                                "type": "keyword"
                            },
                            "reference": {
                                "type": "keyword"
                            }
                        }
                    },
                    "technique": {
                        "properties": {
                            "id": {
                                "type": "keyword"
                            },
                            "name": {
                                "type": "keyword"
                            },
                            "reference": {
                                "type": "keyword"
                            },
                            "subtechnique": {
                                "properties": {
                                    "id": {
                                        "type": "keyword"
                                    },
                                    "name": {
                                        "type": "keyword"
                                    },
                                    "reference": {
                                        "type": "keyword"
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "timestamp_override": {
                "type": "keyword"
            },
            "type": {
                "type": "keyword"
            },
            "version": {
                "type": "integer"
            }
        }
    },
    "settings": {
        "index": {
            "number_of_shards": 1,
            "number_of_replicas": 1
        }
    }
}


def find_json_files(directory):
    """Recursively find all JSON files in the directory."""
    json_files = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.lower().endswith('.json'):
                json_files.append(os.path.join(root, file))
    return json_files


def read_json_file(file_path):
    """Read a JSON file and return its contents."""
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            return json.load(file)
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
        return None


def generate_actions(json_files, index_name):
    """Generate actions for the bulk API."""
    for file_path in json_files:
        data = read_json_file(file_path)
        if data:
            # Handle both single documents and arrays of documents
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        yield {
                            "_index": index_name,
                            "_source": item
                        }
            elif isinstance(data, dict):
                yield {
                    "_index": index_name,
                    "_source": data
                }


def create_index_with_mapping(es_client):
    """
    Create an Elasticsearch index with the specified mapping.
    If the index already exists, it can optionally be deleted and recreated.

    Args:
        es_client: Elasticsearch client instance
        index_name (str): Name of the index to create
        mapping (dict, optional): The mapping configuration. If None, a default mapping will be used.
                                 You can replace this with your custom mapping.

    Returns:
        bool: True if the index was created successfully, False otherwise
    """
    try:
        if es_client.indices.exists(index=ELASTICSEARCH_INDEX):
            print(f"Index '{ELASTICSEARCH_INDEX}' already exists.")
            return True

        # Create the index with the mapping
        print(f"Creating index '{ELASTICSEARCH_INDEX}' with custom mapping...")
        es_client.indices.create(index=ELASTICSEARCH_INDEX, body=MAPPING)
        print(f"Index '{ELASTICSEARCH_INDEX}' created successfully.")
        return True

    except Exception as e:
        print(f"Error creating index with mapping: {e}")
        return False


def upload_data():
    # Validate configuration
    if not os.path.isdir(DIRECTORY_PATH):
        print(f"Error: Directory '{DIRECTORY_PATH}' does not exist.")
        sys.exit(1)

    # Parse URL to ensure it's valid
    try:
        parsed_url = urlparse(ELASTICSEARCH_URL)
        if not parsed_url.scheme or not parsed_url.netloc:
            raise ValueError("Invalid URL format")
    except Exception as e:
        print(f"Error: Invalid Elasticsearch URL: {e}")
        sys.exit(1)

    # Find all JSON files
    json_files = find_json_files(DIRECTORY_PATH)
    if not json_files:
        print(f"No JSON files found in '{DIRECTORY_PATH}'.")
        sys.exit(0)

    print(f"Found {len(json_files)} JSON files to upload.")

    # Connect to Elasticsearch
    try:
        es = Elasticsearch(
            ELASTICSEARCH_URL,
            basic_auth=(ELASTICSEARCH_USERNAME, ELASTICSEARCH_PASSWORD)
        )

        # Check if Elasticsearch is available
        if not es.ping():
            raise ConnectionError("Could not connect to Elasticsearch")

        # Check if index exists, create if it doesn't
        if not es.indices.exists(index=ELASTICSEARCH_INDEX):
            print(
                f"Index '{ELASTICSEARCH_INDEX}' does not exist. Creating it...")
            es.indices.create(index=ELASTICSEARCH_INDEX)

    except Exception as e:
        print(f"Error connecting to Elasticsearch: {e}")
        sys.exit(1)

    # Create index with mapping
    try:
        create_index_with_mapping(es)
    except Exception as e:
        print(f"Error creating index with mapping: {e}")
        sys.exit(1)

    # Upload documents using bulk API
    try:
        success, failed = 0, 0
        actions = generate_actions(json_files, ELASTICSEARCH_INDEX)

        for ok, result in helpers.streaming_bulk(
            es,
            actions,
            max_retries=3,
            yield_ok=True
        ):
            if ok:
                success += 1
            else:
                print(f"Error: {result['index']['error']}")
                failed += 1

            # Print progress every 100 documents
            if (success + failed) % 100 == 0:
                print(f"Progress: {success} succeeded, {failed} failed")
                

        print(
            f"Upload complete: {success} documents uploaded successfully, {failed} documents failed.")

    except Exception as e:
        print(f"Error during bulk upload: {e}")
        sys.exit(1)
