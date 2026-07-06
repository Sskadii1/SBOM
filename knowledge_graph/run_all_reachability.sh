#!/usr/bin/env bash
set -uo pipefail

# This script runs reachability scans for all Python projects found in the Neo4j database.
# Default Neo4j URI can be overridden via command line argument.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

NEO4J_URI="${1:-bolt://host.docker.internal:7689}"
NEO4J_USER="${NEO4J_USER:-neo4j}"
NEO4J_PASSWORD="${NEO4J_PASSWORD:-change_me}"

SUCCESS_COUNT=0
FAIL_COUNT=0
NOT_CRAWLED_COUNT=0
FAILED_PROJECTS=()
NOT_CRAWLED_PROJECTS=()

echo "Fetching project list from Neo4j at $NEO4J_URI..."

# Using python3 to query Neo4j for project list
PROJECTS=$(python3 -c "
import os
from neo4j import GraphDatabase
uri = '$NEO4J_URI'
user = '$NEO4J_USER'
password = '$NEO4J_PASSWORD'
try:
    driver = GraphDatabase.driver(uri, auth=(user, password))
    with driver.session() as session:
        result = session.run('MATCH (p:Project {language: \"Python\"}) RETURN p.full_name as full_name')
        for record in result:
            if record['full_name']:
                print(record['full_name'])
    driver.close()
except Exception as e:
    import sys
    print(f'Error connecting to Neo4j: {e}', file=sys.stderr)
    sys.exit(1)
")

if [ $? -ne 0 ]; then
    echo "Failed to retrieve projects from Neo4j. Exiting."
    exit 1
fi

TOTAL_PROJECTS=$(echo "$PROJECTS" | grep -v "^$" | wc -l | xargs)
echo "Found $TOTAL_PROJECTS Python projects in Neo4j."

# Iterate over projects from Neo4j
for project in $PROJECTS; do
  [ -z "$project" ] && continue

  # Transform owner/repo to owner_repo
  safe_name=$(echo "$project" | tr '/' '_')
  
  # Find the FIRST matching directory in data/vulnerable_repos
  # Names follow pattern: owner_repo__commitsha
  dir_match=$(ls "data/vulnerable_repos/" 2>/dev/null | grep "^${safe_name}__" | head -n 1)

  echo "------------------------------------------------------------"
  if [ -z "$dir_match" ]; then
    echo "[SKIPPED] Project '$project' has not been crawled (missing local directory)."
    NOT_CRAWLED_COUNT=$((NOT_CRAWLED_COUNT + 1))
    NOT_CRAWLED_PROJECTS+=("$project")
    continue
  fi

  repo_path="data/vulnerable_repos/$dir_match"
  echo "Running reachability scan for: $project"
  echo "Local path: $repo_path"
  echo "Neo4j URI: $NEO4J_URI"

  if python3 pipeline_v2.py \
    --project "$project" \
    --repo "$repo_path" \
    --neo4j-uri "$NEO4J_URI" \
    --save \
    --no-ai
  then
    SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
    echo "[OK] Reachability scan successful for $project"
  else
    FAIL_COUNT=$((FAIL_COUNT + 1))
    FAILED_PROJECTS+=("$project")
    echo "[FAIL] Reachability scan failed for $project"
  fi
done

echo "============================================================"
echo "REACHABILITY SCAN SUMMARY"
echo "============================================================"
echo "Total Projects in Neo4j: $TOTAL_PROJECTS"
echo "Successfully Scanned:     $SUCCESS_COUNT"
echo "Not Crawled (Skipped):   $NOT_CRAWLED_COUNT"
echo "Failed Scans:            $FAIL_COUNT"
echo "============================================================"

if [ "$NOT_CRAWLED_COUNT" -gt 0 ]; then
  echo "Not Crawled Projects:"
  for p in "${NOT_CRAWLED_PROJECTS[@]}"; do
    echo "  - $p"
  done
fi

if [ "$FAIL_COUNT" -gt 0 ]; then
  echo "Failed Projects:"
  for p in "${FAILED_PROJECTS[@]}"; do
    echo "  - $p"
  done
  exit 1
fi

exit 0
