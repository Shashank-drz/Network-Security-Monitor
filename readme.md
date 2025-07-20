# NetMon: A Dockerized Network Security Monitor with a Custom C++ Correlation Engine

## Overview

NetMon is a powerful, containerized Network Security Monitoring (NSM) suite designed for real-time analysis of network traffic. It uses the high-performance Suricata IDS engine to generate alerts from network data (PCAP files), which are then processed by a custom-built C++ correlation engine. This allows for flexible, high-speed analysis of security events, with the results visualized in a Grafana dashboard.

## Key Features

- **High-Performance Intrusion Detection**: Utilizes Suricata to analyze network traffic and generate detailed JSON-based event logs.
- **Advanced C++ Alert Correlation**: A lightweight, high-performance correlation engine processes Suricata's output in near real-time.
- **Stateful, Time-Based Analysis**: The engine can track the state of events over time, enabling the detection of complex, multi-stage attack patterns.
- **Flexible Rule Engine**: Correlation rules are defined in a simple YAML file, supporting both simple, stateless checks and complex, stateful sequences.
- **Centralized Logging & Visualization**: Findings are shipped via Promtail to Loki and visualized in a pre-configured Grafana dashboard.
- **Containerized & Portable**: The entire suite is orchestrated with Docker Compose for easy setup and deployment.

## Architecture

The data flows through the NetMon components in a simple, logical pipeline:

```
+-----------------+      +--------------------+      +-----------------+      +------------+      +---------+
|  PCAP File(s)   |----->|      Suricata      |----->|  Correlation    |----->|  Promtail  |----->|   Loki  |
| (Network Data)  |      | (Generates Alerts) |      |  Engine (C++)   |      | (Ships Logs)  |      | (Stores)|
+-----------------+      +--------------------+      +-----------------+      +------------+      +---------+
                                                                                                      ^
                                                                                                      |
                                                                                                +-----------+
                                                                                                |  Grafana  |
                                                                                                | (Queries &|
                                                                                                | Visualizes)|
                                                                                                +-----------+
```

1.  **Suricata**: Reads `.pcap` files from the `app/pcaps` directory and generates alerts in the `eve.json` format.
2.  **Correlation Engine**: The C++ engine (`corr-engine`) monitors `eve.json`, applies the rules from `rules.yaml`, and writes matches to `findings.json`.
3.  **Promtail/Loki**: Promtail tails `findings.json` and sends the findings to Loki for efficient storage and indexing.
4.  **Grafana**: Uses Loki as a data source to populate the "Loki Findings" dashboard for real-time visualization.

## Technology Stack

- **Correlation Engine**: C++
- **Intrusion Detection**: Suricata
- **Log Aggregation**: Grafana Loki
- **Log Shipper**: Grafana Promtail
- **Dashboarding**: Grafana
- **Containerization**: Docker & Docker Compose

## Getting Started

### Prerequisites

- Docker
- Docker Compose

### Installation and Running

1.  **Clone the repository:**
    ```bash
    git clone <your-repo-url>
    cd NetMon/app
    ```

2.  **Add Network Traffic (PCAP files):**
    Place any `.pcap` files you want to analyze into the `app/pcaps` directory. A sample file is already included.

3.  **Build and Launch the Environment:**
    From the `app` directory, run the following commands:
    ```bash
    # Build the services, including the custom C++ engine
    docker-compose build

    # Launch the environment in detached mode
    docker-compose up -d
    ```

4.  **Access the Dashboard:**
    Open your web browser and navigate to `http://localhost:3000`.
    - **Username:** `admin`
    - **Password:** `admin`

    The "Loki Findings" dashboard will be available to view the correlated alerts.

## Customizing Rules

The core of the correlation engine is the `rules.yaml` file, located at `app/corr-engine/rules/rules.yaml`. You can add or modify rules to detect specific patterns. The engine supports two types of rules: `simple` and `sequence`.

### Simple Rules

Simple rules are stateless and trigger on a single event that matches a condition. They support `==`, `!=`, `>=`, `<=`, `>`, and `<` operators.

**Example:**
```yaml
rules:
  - name: "High Severity Alert"
    condition: "alert.severity == 3"
  
  - name: "ICMP Alert"
    condition: "proto == \"ICMP\""
```

### Sequence Rules

Sequence rules are stateful and trigger when two or more simple rules are matched by the **same source IP** within a defined `time_window`. This is powerful for detecting multi-stage activity.

**Example:**
This rule triggers if a `Spotify P2P Client Detected` event is followed by a `High Severity Alert` from the same IP within 60 seconds.

```yaml
rules:
  # First, define the simple rules that make up the sequence
  - name: "Spotify P2P Client Detected"
    condition: "alert.signature == \"ET INFO Spotify P2P Client\""
  
  - name: "High Severity Alert"
    condition: "alert.severity == 3"

  # Then, define the sequence rule that uses them
  - name: "Spotify Followed by High Severity Alert"
    sequence:
      time_window: 60 # in seconds
      rules:
        - "Spotify P2P Client Detected"
        - "High Severity Alert"
```

### Applying Changes

After modifying `rules.yaml`, you must rebuild and restart the containers.

```bash
# From the app directory:

# Optional: Clear previous findings for a clean slate
sudo rm ./logs/corr_engine_output/findings.json

# Rebuild and restart the services to apply new rules
docker-compose up -d --force-recreate --build
```

## Troubleshooting

For common issues, such as Docker DNS errors or Grafana permission problems, please refer to the [troubleshooting guide](./troubleshooting.md).
