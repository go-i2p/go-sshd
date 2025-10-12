# Performance Monitoring Guide

## Overview

sshd-go includes comprehensive performance monitoring using Prometheus metrics and health check endpoints. This feature is **disabled by default** and must be explicitly enabled in the configuration.

## Library Architecture

**Metrics Implementation**: [prometheus/client_golang](https://github.com/prometheus/client_golang) v1.23+

Following the project's library-first philosophy, all metrics functionality is provided by the mature Prometheus client library with zero custom protocol implementation. The metrics system consists of ~300 lines of wrapper code around prometheus/client_golang.

## Configuration

Add the following directives to your `sshd_config`:

```sshd_config
# Enable Prometheus metrics endpoint
MetricsEnabled yes

# Metrics HTTP server address (default: 127.0.0.1:9100)
MetricsAddress 127.0.0.1:9100
```

### Configuration Directives

| Directive | Values | Default | Description |
|-----------|--------|---------|-------------|
| `MetricsEnabled` | yes/no | no | Enable/disable metrics collection and HTTP endpoint |
| `MetricsAddress` | host:port | 127.0.0.1:9100 | Address where metrics HTTP server listens |

**Security Note**: By default, metrics listen only on localhost (127.0.0.1). To expose metrics to external monitoring systems, use `0.0.0.0:9100` but ensure proper firewall configuration.

## Available Endpoints

When metrics are enabled, the following HTTP endpoints are available:

### `/metrics` - Prometheus Metrics

Returns metrics in Prometheus exposition format (OpenMetrics compatible).

```bash
curl http://localhost:9100/metrics
```

### `/health` - Health Check

Returns detailed health status as JSON. Suitable for load balancer health checks.

```bash
curl http://localhost:9100/health
```

Response format:
```json
{
  "status": "ok",
  "active_conns": 5,
  "active_sessions": 3,
  "config_valid": true
}
```

Status values:
- `ok`: Server operating normally
- `degraded`: Server functional but with issues (e.g., invalid config)
- `error`: Server experiencing errors

### `/ready` - Readiness Probe

Returns simple text response for Kubernetes/container orchestration readiness probes.

```bash
curl http://localhost:9100/ready
```

Returns:
- `200 OK` with body `ready` when server is ready
- `503 Service Unavailable` with body `not ready` when server has errors

## Available Metrics

### Connection Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `sshd_connections_total` | Counter | Total SSH connections accepted |
| `sshd_connections_active` | Gauge | Current active SSH connections |
| `sshd_connection_duration_seconds` | Histogram | Connection duration distribution |

### Authentication Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `sshd_auth_attempts_total` | Counter | method, result | Authentication attempts by method and result |

Label values:
- `method`: `publickey`, `password`
- `result`: `success`, `failure`

### Session Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `sshd_sessions_total` | Counter | Total SSH sessions started |
| `sshd_sessions_active` | Gauge | Current active sessions (shell, SFTP, etc) |

### Data Transfer Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `sshd_bytes_transferred_total` | Counter | direction | Total bytes transferred |

Label values:
- `direction`: `sent`, `received`

### Request Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `sshd_requests_total` | Counter | type, result | Requests by type and result |
| `sshd_request_duration_seconds` | Histogram | type | Request duration by type |

Label values:
- `type`: `shell`, `sftp`, `forward`
- `result`: `success`, `failure`

## Prometheus Integration

### Basic Prometheus Configuration

Add the following to your `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'sshd-go'
    static_configs:
      - targets: ['localhost:9100']
        labels:
          instance: 'sshd-primary'
          service: 'ssh'
```

### Example Queries

**Connection rate (per minute)**:
```promql
rate(sshd_connections_total[1m])
```

**Authentication failure rate**:
```promql
rate(sshd_auth_attempts_total{result="failure"}[5m])
```

**Active sessions**:
```promql
sshd_sessions_active
```

**Connection duration 95th percentile**:
```promql
histogram_quantile(0.95, sshd_connection_duration_seconds_bucket)
```

**Data transfer rate (bytes/sec)**:
```promql
rate(sshd_bytes_transferred_total[1m])
```

## Grafana Dashboard

### Recommended Panels

1. **Connection Overview**
   - Current active connections (Gauge)
   - Connection rate over time (Graph)
   - Connection duration histogram (Heatmap)

2. **Authentication**
   - Success vs failure rate (Graph)
   - Authentication methods distribution (Pie chart)
   - Failed authentication attempts (Table)

3. **Sessions**
   - Active sessions by type (Stacked graph)
   - Session duration (Graph)
   - Session requests per minute (Graph)

4. **Data Transfer**
   - Network throughput (sent/received) (Graph)
   - Total data transferred (Single stat)

5. **Health**
   - Server status (Single stat with thresholds)
   - Configuration validity (Boolean indicator)

### Sample PromQL for Panels

**Total connections today**:
```promql
increase(sshd_connections_total[24h])
```

**Authentication success rate**:
```promql
sum(rate(sshd_auth_attempts_total{result="success"}[5m])) 
/ 
sum(rate(sshd_auth_attempts_total[5m]))
* 100
```

**Top users by session count** (requires integration):
```promql
topk(10, increase(sshd_sessions_total[1h]))
```

## Kubernetes Integration

### Deployment with Metrics

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: sshd-config
data:
  sshd_config: |
    Port 22
    MetricsEnabled yes
    MetricsAddress 0.0.0.0:9100
---
apiVersion: v1
kind: Service
metadata:
  name: sshd-metrics
  labels:
    app: sshd-go
spec:
  ports:
    - name: metrics
      port: 9100
      targetPort: 9100
  selector:
    app: sshd-go
  type: ClusterIP
---
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: sshd-monitor
spec:
  selector:
    matchLabels:
      app: sshd-go
  endpoints:
    - port: metrics
      interval: 30s
```

### Liveness and Readiness Probes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: sshd-go
spec:
  template:
    spec:
      containers:
        - name: sshd
          image: sshd-go:latest
          ports:
            - containerPort: 22
              name: ssh
            - containerPort: 9100
              name: metrics
          livenessProbe:
            httpGet:
              path: /health
              port: metrics
            initialDelaySeconds: 10
            periodSeconds: 30
          readinessProbe:
            httpGet:
              path: /ready
              port: metrics
            initialDelaySeconds: 5
            periodSeconds: 10
```

## Security Considerations

### Firewall Configuration

Metrics endpoint should be protected:

```bash
# Allow metrics only from monitoring server
sudo ufw allow from 10.0.1.100 to any port 9100 proto tcp

# Or restrict to localhost only (default)
# No firewall rule needed - listening on 127.0.0.1
```

### Network Segmentation

Recommended deployment patterns:

1. **Localhost only** (default): Metrics accessed via reverse proxy or port forwarding
2. **Management network**: Bind to management interface IP
3. **All interfaces**: Use with proper firewall rules and consider TLS reverse proxy

### TLS Protection

While sshd-go metrics endpoint doesn't include built-in TLS, you can use a reverse proxy:

```nginx
server {
    listen 9100 ssl;
    ssl_certificate /etc/ssl/certs/metrics.crt;
    ssl_certificate_key /etc/ssl/private/metrics.key;
    
    location / {
        proxy_pass http://127.0.0.1:9100;
    }
}
```

## Alerting Rules

### Prometheus Alert Examples

```yaml
groups:
  - name: sshd_alerts
    interval: 30s
    rules:
      - alert: SSHDHighFailedAuth
        expr: rate(sshd_auth_attempts_total{result="failure"}[5m]) > 10
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "High authentication failure rate on {{ $labels.instance }}"
          description: "{{ $value }} failed auth attempts per second"

      - alert: SSHDNoActiveConnections
        expr: sshd_connections_active == 0
        for: 1h
        labels:
          severity: info
        annotations:
          summary: "No active SSH connections on {{ $labels.instance }}"
          description: "Server has had no active connections for 1 hour"

      - alert: SSHDHighConnectionDuration
        expr: histogram_quantile(0.95, sshd_connection_duration_seconds_bucket) > 3600
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Long-running SSH connections on {{ $labels.instance }}"
          description: "95th percentile connection duration: {{ $value }}s"
```

## Performance Impact

### Resource Usage

- **Memory**: ~5MB additional for metrics collection
- **CPU**: <1% overhead for metric updates
- **Network**: ~50KB/scrape for metrics endpoint

### Recommendations

- Use 30-60 second scrape intervals for production
- Shorter intervals (5-10s) only for debugging
- Metrics endpoint timeout: 5-10 seconds

## Troubleshooting

### Metrics endpoint not accessible

```bash
# Check if metrics are enabled
./sshd -t

# Verify metrics server is listening
netstat -tlnp | grep 9100

# Test metrics endpoint
curl -v http://localhost:9100/metrics
```

### No metrics appearing

```bash
# Verify Prometheus scrape configuration
curl http://prometheus:9090/api/v1/targets

# Check Prometheus logs
journalctl -u prometheus -f
```

### High cardinality warnings

If you see high cardinality warnings in Prometheus:
- This shouldn't occur with default metrics (all have controlled label sets)
- Check for custom label additions in wrapped metrics

## Integration Examples

### Docker Compose

```yaml
version: '3.8'
services:
  sshd:
    image: sshd-go:latest
    ports:
      - "22:22"
    volumes:
      - ./sshd_config:/etc/ssh/sshd_config:ro
    networks:
      - monitoring

  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml:ro
    networks:
      - monitoring

  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
    networks:
      - monitoring

networks:
  monitoring:
```

## Further Reading

- [Prometheus Documentation](https://prometheus.io/docs/introduction/overview/)
- [Prometheus Best Practices](https://prometheus.io/docs/practices/naming/)
- [Grafana Documentation](https://grafana.com/docs/)
- [OpenMetrics Specification](https://openmetrics.io/)
