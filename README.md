# Domain Monitor

Python 域名全方位检测平台，包含 Web 面板、登录认证、多用户权限、域名分组、通知静默、Prometheus 指标、Grafana Dashboard、SSL/Whois/Ping/HTTP/DNS 检测、失败 N 次告警、恢复通知、告警升级策略，并提供 Kubernetes 部署资源。

## 功能

- 登录认证：默认管理员由 `ADMIN_USERNAME` / `ADMIN_PASSWORD` 初始化。
- 多用户权限：admin / user / readonly。
- 域名分组：支持按业务或环境分组。
- 检测项：DNS A 记录、TCP 端口、HTTP/HTTPS、SSL 证书、Whois 到期、ICMP Ping。
- 告警策略：失败阈值、恢复阈值、静默时间、升级时间。
- 降噪策略：`warning` 默认需要更长连续触发次数才发送通知，域名级响应时间按已成功 URL 的平均值统计，避免单个慢路径放大成整站告警。
- 通知渠道：企业微信、Telegram、both。
- Metrics：`/metrics` 暴露 Prometheus 指标。
- K8s：所有资源放在 `monitor` 命名空间，PostgreSQL PVC 使用 `efs-prod-sc`。

## 本地运行

```bash
pip install -r requirements.txt
cd app
export DATABASE_URL="sqlite:///./domain_monitor.db"
export SECRET_KEY="dev-secret"
export ADMIN_USERNAME="admin"
export ADMIN_PASSWORD="Admin@123456"
uvicorn main:app --host 0.0.0.0 --port 8000
```

访问：`http://127.0.0.1:8000`

## 构建镜像

```bash
./scripts/build-and-push.sh your-registry/domain-monitor:latest
```

然后将 `k8s/04-web-worker-agent.yaml` 和 `k8s/09-init-admin-job.yaml` 中的镜像替换为你的镜像地址：

```bash
sed -i 's#your-registry/domain-monitor:latest#你的镜像地址#g' k8s/*.yaml
```

## Kubernetes 部署

资源默认部署到现有 `monitor` 命名空间，PostgreSQL PVC 使用默认存储类 `efs-prod-sc`。

```bash
kubectl apply -k k8s
kubectl get pod -n monitor | grep domain-monitor
kubectl get pvc -n monitor | grep domain-monitor
kubectl get svc -n monitor | grep domain-monitor
```

NodePort 访问：

```text
http://任意K8s节点IP:30888
```

Ingress 访问默认示例：

```text
https://domain-monitor.ug1686688.com
```

如不使用 APISIX，请修改 `k8s/06-ingress.yaml` 的 `ingressClassName`。

## 默认账号

来自 Secret：

```text
ADMIN_USERNAME=admin
ADMIN_PASSWORD=Admin@123456
```

生产环境必须修改 `SECRET_KEY`、`ADMIN_PASSWORD`、数据库密码和通知 Webhook。

## Prometheus 指标

```promql
domain_monitor_up
domain_monitor_http_status_code
domain_monitor_response_time_ms
domain_monitor_ssl_days_left
domain_monitor_whois_days_left
domain_monitor_fail_count
domain_monitor_alert_total
```

ServiceMonitor 标签默认是：

```yaml
release: monitor
```

如果你的 Prometheus Operator 选择器不是这个标签，请修改 `k8s/07-servicemonitor.yaml` 和 `k8s/08-prometheusrule.yaml`。

## Grafana Dashboard

导入：

```text
grafana/domain-monitor-dashboard.json
```

## 注意事项

1. ICMP Ping 需要容器具备 `NET_RAW` 能力，已在 agent Deployment 中添加。
2. 云环境可能禁用 ICMP，Ping 失败不一定代表域名不可用，建议以 HTTP/TCP/SSL 为主。
3. EFS 上运行 PostgreSQL 可用于测试或轻量场景，生产建议改用 RDS PostgreSQL。
4. Worker 和 Agent 当前使用同一套检测逻辑。多地域部署时，为每个 Agent 配置不同 `AGENT_NAME` 与 `AGENT_REGION` 即可区分来源。
