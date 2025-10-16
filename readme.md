# NetMon: Network Security Monitor with Real-Time Correlation Engine
[![License](https://img.shields.io/github/license/Shashank-drz/Network-Security-Monitor)](LICENSE)

## Overview

NetMon is a containerized Network Security Monitoring (NSM) platform built for analyzing network traffic in real-time. It combines **Suricata IDS** for deep packet inspection with a **custom C++ correlation engine** that detects multi-stage attacks by analyzing event sequences across time.

Unlike traditional SIEM solutions, NetMon's correlation engine is:
- **Lightweight & Fast**: Written in C++17 for minimal latency
- **Stateful**: Tracks attack patterns across multiple events and time windows
- **Flexible**: Rule-based detection using simple YAML configuration
- **Real-Time**: Processes alerts as they're generated, not in batches

All findings are centralized in **Grafana** via **Loki**, providing instant visibility into correlated threats.

## Dashboard Preview
<details>
  <summary>Click to view dashboard screenshots</summary>
  <p align="center">
    <em>Main Dashboard Overview</em><br>
    <img src="screenshots/S1.png" alt="Main Dashboard">
    <br><br>
    <em>Correlated Findings Timeline</em><br>
    <img src="screenshots/S3.png" alt="Detailed Alert View">
  </p>
</details>

## Key Features

### 🚀 **Real-Time Threat Detection**
- **Suricata IDS** processes network traffic and generates JSON alerts (EVE format)
- **C++ Correlation Engine** analyzes alert streams in real-time with sub-second latency
- Detects both simple threats (signature matches) and complex attack chains (sequences)

### 🔗 **Stateful Correlation**
- Tracks events per source IP across configurable time windows
- Identifies multi-stage attacks (e.g., reconnaissance → exploitation)
- Correlates related events into unified findings

### 📊 **Centralized Visualization**
- **Promtail** ships findings to **Loki** for indexing
- **Grafana** dashboards query Loki for instant threat visibility
- Built-in dashboard for correlation findings with filtering by rule, IP, severity

### ⚙️ **Flexible Rule Engine**
Define detection logic in YAML without recompiling:

```yaml
# Simple pattern matching
- name: "Malicious TOP Domain Query Detected"
  condition: 'alert.signature == "ET DNS Query to a *.top domain - Likely Hostile"'

# Sequence-based detection (stateful)
- name: "Correlated Attack: Port Scan followed by Exploit"
  sequence:
    rules:
      - "Potential Port Scan Detected"
      - "Exploit Attempt Detected"
    time_window: 60  # seconds
```

### 🐳 **Fully Containerized**
- Orchestrated with Docker Compose for one-command deployment
- Isolated services with health checks and auto-restart
- Volume-based data persistence

## Architecture

```
┌──────────────┐      ┌────────────────┐      ┌──────────────────┐      ┌───────────┐
│  PCAP Files  │─────▶│   Suricata     │─────▶│  Correlation     │─────▶│ Promtail  │
│ (Network     │      │ (IDS Engine)   │      │  Engine (C++17)  │      │ (Log      │
│  Traffic)    │      │ Generates Alerts│      │  Stateful Rules  │      │  Shipper) │
└──────────────┘      └────────────────┘      └──────────────────┘      └─────┬─────┘
                           │                         │                          │
                           │ eve.json                │ findings.json            │
                           ▼                         ▼                          ▼
                      ┌─────────────────────────────────────────────────────────┐
                      │                     Loki (Log Store)                     │
                      └────────────────────────┬────────────────────────────────┘
                                               │
                                               ▼
                                          ┌─────────┐
                                          │ Grafana │
                                          │Dashboard│
                                          └─────────┘
```

### Data Flow

1. **Ingestion**: Suricata reads PCAPs and generates `eve.json` (alert stream)
2. **Correlation**: C++ engine monitors `eve.json`, applies rules from `rules.yaml`, writes matches to `findings.json`
3. **Indexing**: Promtail tails `findings.json` and ships logs to Loki
4. **Visualization**: Grafana queries Loki and displays findings in real-time

### Timestamp Handling

The correlation engine generates **current timestamps** for detection events while preserving **original PCAP timestamps** for forensic analysis:

```json
{
  "timestamp": "2025-10-16T19:12:45.123456+0000",          // Detection time
  "original_timestamp": "2025-08-13T22:00:22.522093+0000", // Event time from PCAP
  "rule_name": "Malicious TOP Domain Query Detected",
  "correlation_id": "4fd1e89a-5f8f-49fb-8ad3-60d948061594"
}
```

This allows analyzing historical PCAPs without Loki rejecting "old" timestamps.

## Getting Started

### Prerequisites

- **Docker** (20.10+)
- **Docker Compose** (1.29+)
- At least 2GB RAM and 10GB disk space

### Quick Start

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Shashank-drz/Network-Security-Monitor.git
   cd Network-Security-Monitor/app
   ```

2. **Add Network Traffic:**
   Place `.pcap` files in the `pcaps/` directory. A sample Lumma Stealer PCAP is included for testing.

3. **Launch the Stack:**
   ```bash
   docker compose up -d --build
   ```

   This will:
   - Build the C++ correlation engine
   - Start Suricata, Loki, Promtail, and Grafana
   - Begin processing PCAPs automatically

4. **Access Grafana:**
   - URL: `http://localhost:3000`
   - Username: `admin`
   - Password: `NSMadmin`
   
   Navigate to **Dashboards** → **Correlation Engine Findings (Loki)**

### Verifying the Setup

```bash
# Check all containers are running
docker compose ps

# View correlation findings in real-time
tail -f findings/findings.json

# Check Loki has received data
curl -s "http://localhost:3100/loki/api/v1/label/job/values" | jq

# Query findings via Loki API
curl -G -s "http://localhost:3100/loki/api/v1/query" \
  --data-urlencode 'query={job="corr-engine-findings"}' \
  --data-urlencode 'limit=5' | jq
```

## Customizing Detection Rules

Rules are defined in `corr-engine/rules/rules.yaml`. The engine supports two types:

### 1. Simple Rules (Stateless)
Match individual events based on field conditions:

```yaml
- name: "High Severity Alert"
  condition: "alert.severity == 1"

- name: "Potential Data Exfiltration"
  condition: 'alert.category == "Potentially Bad Traffic"'
```

### 2. Sequence Rules (Stateful)
Detect multi-event attack patterns within a time window:

```yaml
- name: "Reconnaissance Followed by Exploit"
  sequence:
    rules:
      - "Potential Port Scan Detected"
      - "Exploit Attempt Detected"
    time_window: 300  # 5 minutes
```

### Supported Operators
- `==`, `!=`: String/numeric equality
- `>`, `<`, `>=`, `<=`: Numeric comparison
- Nested field access: `alert.metadata.signature_severity`

### Applying Rule Changes

After modifying `rules.yaml`:

```bash
# Rebuild and restart the correlation engine
docker compose up -d --force-recreate correlation-engine
```

No recompilation needed for rule changes!

## Configuration

### Loki Retention Settings
Edit `loki/loki-config.yaml`:

```yaml
limits_config:
  reject_old_samples_max_age: 2160h  # 90 days (for PCAP replay)
  retention_period: 720h              # 30 days data retention
```

### Promtail Log Shipping
Edit `promtail-config.yml` to adjust:
- Batch sizes (`batchsize`, `batchwait`)
- Label extraction (avoid high-cardinality labels)
- Timestamp parsing formats

### Resource Limits
Adjust in `docker-compose.yml`:

```yaml
services:
  correlation-engine:
    mem_limit: 256m  # Increase if processing large PCAPs
  
  loki:
    mem_limit: 512m  # Increase for longer retention
```

## Troubleshooting

### Container Issues

```bash
# View logs for specific service
docker compose logs -f correlation-engine

# Restart all services
docker compose restart

# Clean slate restart
docker compose down
docker compose up -d --build
```

### Common Problems

| Issue | Solution |
|-------|----------|
| **No findings generated** | Check `docker logs netmon-corr-engine` for rule parsing errors |
| **Grafana shows no data** | Verify Loki connection: `curl http://localhost:3100/ready` |
| **Promtail not sending logs** | Check `docker logs netmon-promtail` for timestamp parsing errors |
| **Suricata crash loop** | Ensure PCAPs are valid: `file pcaps/*.pcap` |

For detailed troubleshooting, see [docs/troubleshooting.md](./docs/troubleshooting.md).

## Performance Characteristics

- **Throughput**: ~10,000 alerts/second on 4-core CPU
- **Latency**: <10ms per event correlation
- **Memory**: ~50MB baseline (correlation engine)
- **Storage**: ~1MB per 1000 findings (compressed in Loki)

## Project Structure

```
Network-Security-Monitor/
├── app/
│   ├── corr-engine/           # C++ correlation engine source
│   │   ├── src/corr_engine.cpp
│   │   ├── rules/rules.yaml   # Detection rules
│   │   ├── CMakeLists.txt
│   │   └── Dockerfile
│   ├── loki/
│   │   └── loki-config.yaml   # Loki configuration
│   ├── promtail-config.yml    # Log shipper config
│   ├── grafana/
│   │   └── provisioning/      # Auto-provisioned dashboards
│   ├── pcaps/                 # Input network captures
│   ├── findings/              # Correlation output
│   ├── logs/suricata/         # Suricata EVE logs
│   └── docker-compose.yml     # Service orchestration
├── docs/
│   └── troubleshooting.md
└── README.md
```

## Roadmap

- [ ] Add support for custom Suricata rule files
- [ ] Implement MITRE ATT&CK tagging in findings
- [ ] Add ML-based anomaly detection module
- [ ] Support live network interfaces (not just PCAPs)
- [ ] Integrate with SIEM platforms (Splunk, ELK)
- [ ] Add automated response actions (firewall rules, alerts)

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

MIT License © 2025 Shashank. See [LICENSE](LICENSE) for full text.

## Acknowledgments

- **Suricata** - Open-source IDS/IPS engine
- **Grafana Labs** - Loki, Promtail, and Grafana
- **nlohmann/json** - Modern C++ JSON library
- **yaml-cpp** - YAML parser for C++

---

**Built with ❤️ for network security enthusiasts**
