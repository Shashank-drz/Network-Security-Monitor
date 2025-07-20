# Troubleshooting Common Errors

This document covers common issues that may arise when setting up the project environment.

---

### 1. Build fails for `corr-engine` with DNS error

**Symptom:**

When running `docker compose up -d`, the build process fails with an error similar to this:

```
failed to solve: ubuntu:22.04: failed to resolve source metadata for ... dial tcp: lookup ... on 127.0.0.53:53: server misbehaving
```

**Cause:**

The Docker daemon is unable to resolve the DNS for the Ubuntu image repository. This is often due to an incompatibility with the host system's local DNS resolver.

**Solution:**

Configure the Docker daemon to use a specific public DNS server.

1.  Create or overwrite Docker's daemon configuration to use Google's DNS:
    ```bash
    echo '{"dns": ["8.8.8.8", "8.8.4.4"]}' | sudo tee /etc/docker/daemon.json
    ```

2.  Restart the Docker service to apply the changes:
    ```bash
    sudo systemctl restart docker
    ```

After restarting, run `docker compose up -d` again from the `nsm-cpp-engine` directory.

---

### 2. Grafana container is stuck in a restart loop

**Symptom:**

After running `docker compose up -d`, the output of `docker ps` shows the `nsm_grafana` container is continuously `Restarting`.

Checking the logs with `docker logs nsm_grafana` shows a permission error:

```
GF_PATHS_DATA='/var/lib/grafana' is not writable.
mkdir: can't create directory '/var/lib/grafana/plugins': Permission denied
```

**Cause:**

The Grafana process inside the container does not have permission to write to the data directory (`./nsm-cpp-engine/logs/grafana_data`) on the host machine. This happens because the directory is owned by `root`, but the container runs as `user: "1000"`.

**Solution:**

Change the ownership of the host directory to match the user ID in the container.

1.  Navigate to the `nsm-cpp-engine` directory and stop the services if they are running:
    ```bash
    cd nsm-cpp-engine
    docker compose down
    ```

2.  Change the directory ownership. This command must be run from the `nsm-cpp-engine` directory.
    ```bash
    sudo chown -R 1000:1000 ./logs/grafana_data
    ```

3.  Restart the services:
    ```bash
    docker compose up -d
    ```
