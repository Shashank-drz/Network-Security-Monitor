# Troubleshooting NetMon NSM Stack

This guide covers common issues with Docker Compose setup for Suricata, correlation-engine, Loki, Promtail, and Grafana. Run `docker compose logs <service>` for details. Assumes lumma_stealer.pcap in `./pcaps/` for testing.

## General Startup Issues

### All Services Restarting (Exit Code 1)
- **Cause**: Config parse failures or missing volumes.
- **Fix**:
  - Ensure directories: `mkdir -p loki pcaps logs/suricata findings grafana/provisioning corr-engine/rules corr-engine/build`.
  - Download PCAP: `wget -O pcaps/lumma_stealer.pcap https://github.com/Shashank-drz/Network-Security-Monitor/raw/main/app/pcaps/lumma_stealer.pcap`.
  - Restart: `docker compose down -v && docker compose up -d --build`.
  - Check: `sleep 90 && docker compose ps` (expect all Up/healthy). If not, `docker compose logs -f` for errors.

### No Data in Grafana Dashboards
- **Cause**: Loki/Promtail not ingesting eve.json/findings.json.
- **Fix**:
  - Verify files: `ls -lh logs/suricata/eve.json` (>1MB with alerts), `tail findings/findings.json` (correlations like "Malicious TOP Domain Query Detected").
  - Test Loki: `curl -G "http://localhost:3100/loki/api/v1/query" --data-urlencode 'query={job="suricata-logs"}' --data-urlencode 'limit=5' | jq` (returns alerts).
  - Grafana: localhost:3000 (admin/NSMadmin) > Connections > Add Loki (http://loki:3100) > Explore `{job="suricata-logs"}` (shows timelines). If empty, restart Promtail: `docker compose restart promtail`.

## Loki-Specific Issues

### Loki Restarting with Schema Validation Errors
- **Symptoms**: Logs show "schema v13 required... boltdb-shipper v12" or "structured metadata" errors.
- **Cause**: Loki 3.0.0 defaults to structured metadata (OTLP), incompatible with v12 schema without disable flag.
- **Fix**:
  - Edit `./loki/local-config.yaml`: Add `allow_structured_metadata: false` under `limits_config`.
  - Restart: `docker compose down -v loki && docker compose up -d loki`.
  - Verify: `docker compose logs loki | tail -10` ("Starting Loki", "http-listening on :3100", no validation errors).
  - Upgrade Note: For production, migrate to tsdb/v13 schema (see [Loki Docs](https://grafana.com/docs/loki/latest/fundamentals/architecture/components/index-store/#schema-configuration)).

### Loki "Failed Parsing Config" (YAML Unmarshal)
- **Symptoms**: "field path not found" or "storage/ring not found" errors.
- **Cause**: Invalid YAML structure (e.g., common.path vs path_prefix; misplaced storage/ring).
- **Fix**:
  - Use the provided minimal config in repo (boltdb-shipper v12 for dev).
  - Test: `docker run --rm -v $(pwd)/loki:/etc/loki grafana/loki:3.0.0 -config.file=/etc/loki/local-config.yaml version` (no errors).
  - Ensure mount: `./loki:/etc/loki` in docker-compose.yml; file at `./loki/local-config.yaml`.

## Promtail-Specific Issues

### Promtail Restarting with "__path__ not found" Error
- **Symptoms**: YAML unmarshal on lines ~26/51: "field __path__ not found in static_configs".
- **Cause**: __path__ must be under `labels` in `static_configs` (special label for file paths); invalid nesting.
- **Fix**:
  - Edit `./promtail-config.yml`: Ensure structure like:
    ```
    static_configs:
      - targets: [localhost]
        labels:
          job: suricata-logs
          __path__: /var/log/suricata/eve.json
    ```
  - Add `-config.expand-env=true` to Promtail command in docker-compose.yml.
  - Restart: `docker compose restart promtail`.
  - Verify: `docker compose logs promtail | tail -10` ("Promtail started", "Successfully sent batch").

### Promtail Not Shipping Logs (No Batches in Logs)
- **Cause**: Pipeline failures on JSON/timestamp parse (eve.json malformed) or Loki down.
- **Fix**:
  - Add `action_on_failure: skip` to json/timestamp stages in promtail-config.yml (skips bad lines from PCAP replays).
  - Check positions: `docker compose down -v promtail` (clears /tmp/positions.yaml; restarts tailing).
  - Verify: `docker compose logs promtail | grep batch` (sent entries from eve.json).

## Suricata/Correlation-Engine Issues

### Suricata Restarting or No eve.json
- **Symptoms**: "health: starting" forever; no "Processing PCAPs..." logs.
- **Cause**: Entrypoint interference or missing PCAPs.
- **Fix**:
  - docker-compose.yml: Use `entrypoint: /bin/sh` and `command: -c "..."` for loop.
  - Ensure PCAP: `ls pcaps/*.pcap`; add if empty.
  - Restart: `docker compose restart suricata`.
  - Verify: `docker compose logs suricata | grep Processing` (runs suricata -r on lumma_stealer.pcap); `wc -l logs/suricata/eve.json` (>100 lines).

### No findings.json or Engine Errors
- **Symptoms**: Engine healthy but empty findings.json; "Loaded 0 rules".
- **Cause**: Rules.yaml parse fail or eve.json empty.
- **Fix**:
  - Check rules: `cat corr-engine/rules/rules.yaml` (7 rules, e.g., TOP domain).
  - Engine logs: `docker compose logs correlation-engine` ("Loaded 7 rules", tailing eve.json).
  - Verify: `tail findings/findings.json` (e.g., {"rule_name": "Malicious TOP Domain Query Detected"}).

### Build Failures (CPP/Engine)
- **Symptoms**: "correlation-engine" build errors (e.g., missing deps, CMake fail).
- **Cause**: Outdated Dockerfile/CMakeLists.txt or missing libs (nlohmann/json, yaml-cpp).
- **Fix**:
  - Dockerfile: Ensure `apt update && apt install -y cmake g++ libyaml-cpp-dev nlohmann-json3-dev`.
  - CMakeLists.txt: Add `find_package(yaml-cpp REQUIRED)` and `target_link_libraries(corr_engine yaml-cpp::yaml-cpp)`.
  - Rebuild: `docker compose build --no-cache correlation-engine`.
  - Verify: `docker compose logs correlation-engine` ("Loaded 7 rules", no segfaults in JSON parse).

## Grafana-Specific Issues

### Empty Dashboards/No Loki Datasource
- **Cause**: Loki not reachable (restarts) or wrong URL.
- **Fix**:
  - Add datasource: localhost:3000 > Connections > Loki (URL: http://loki:3100) > Save & Test.
  - Query: Explore > `{job="suricata-logs"} |~ "alert"` (malware alerts); `{job="corr-engine-findings"}` (correlations).
  - Provisioning: Ensure `./grafana/provisioning/datasources/loki-datasource.yaml` points to http://loki:3100 (auto-adds on startup).

## Performance/Prod Tips

- **High CPU/Memory**: Increase mem_limit (e.g., Loki 1GB for >10GB logs; engine 512m for large eve.json).
- **No Real-Time Data**: PCAP loop sleeps 10s; for live traffic, mount interface: `- --pfring-int=eth0` in Suricata volumes.
- **Logs Cleanup**: `docker compose down -v && rm -rf logs findings loki-data grafana-data`.
- **Debug**: Add `-log.level=debug` to Loki/Promtail commands for verbose output.

For more, see [Loki Docs](https://grafana.com/docs/loki/latest/) or repo issues.
