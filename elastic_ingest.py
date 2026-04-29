#!/usr/env/bin python3
"""
elastic_ingest.py
Pushes incidents_correlated.json into Elasticsearch.
"""
import json
import argparse
from pathlib import Path
try:
    from elasticsearch import Elasticsearch, helpers
except ImportError:
    print("Please install elasticsearch package: pip install elasticsearch")
    exit(1)

def ingest_to_elk(json_path: Path):
    if not json_path.exists():
        print(f"File not found: {json_path}")
        return

    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Disable security for local dev
    es = Elasticsearch("http://localhost:9200")
    
    if not es.ping():
        print("❌ Could not connect to Elasticsearch at http://localhost:9200")
        print("Make sure your docker-compose is running!")
        return

    index_name = "v1_recon-incidents"
    
    actions = []
    # Ingest High Severity
    for inc in data.get("high_severity", []):
        inc["severity_level"] = "HIGH"
        actions.append({
            "_index": index_name,
            "_source": inc
        })
        
    # Ingest Medium Severity
    for inc in data.get("medium_severity", []):
        inc["severity_level"] = "MEDIUM"
        actions.append({
            "_index": index_name,
            "_source": inc
        })

    if not actions:
        print("No incidents to ingest.")
        return

    print(f"Ingesting {len(actions)} incidents into Elasticsearch index '{index_name}'...")
    helpers.bulk(es, actions)
    print("✅ Ingestion complete! Open Kibana at http://localhost:5601")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("json_file", type=Path, help="Path to incidents_correlated.json")
    args = parser.parse_args()
    ingest_to_elk(args.json_file)
