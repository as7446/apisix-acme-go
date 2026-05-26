# apisix-acme-go

APISIX 证书自动申请、续期与多 Agent 同步服务。

## 架构

项目只保留两种运行角色，使用同一个二进制通过 `mode` 切换：

- `controller`: 提供 API、执行 ACME 签发、调度 Agent 任务、做漂移检测。
- `agent`: 注册到 Controller，长轮询任务，在本地 APISIX 执行 `inject_challenge`、`remove_challenge`、`sync_cert`、`delete_cert`。

Controller 不再直接访问 APISIX Admin API。

## 构建

```bash
go build -o certmanager ./cmd/certmanager
```

## 配置

Controller:

```bash
cp config.controller.example.yml config.yml
```

Agent:

```bash
cp config.agent.example.yml config.yml
```

运行时默认读取当前目录的 `config.yml`，也可以通过 `CONFIG_PATH` 指定。

## 启动

Controller:

```bash
CONFIG_PATH=config.controller.example.yml ./certmanager
```

Agent:

```bash
CONFIG_PATH=config.agent.example.yml ./certmanager
```

## REST API

创建证书：

```bash
curl -X POST "http://127.0.0.1:8080/v1/certificates" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer changeme" \
  -d '{"domain":"example.com","force":false,"challenge_zone":"hk","sync_zones":["hk"]}'
```

查询证书：

```bash
curl "http://127.0.0.1:8080/v1/certificates/example.com" \
  -H "Authorization: Bearer changeme"
```

更新证书 Agent 路由策略：

```bash
curl -X PATCH "http://127.0.0.1:8080/v1/certificates/example.com/routing" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer changeme" \
  -d '{"challenge_zone":"hk","sync_zones":["hk","sg"]}'
```

`challenge_zone` 影响下一次签发或续签时由哪个 Agent 建立 HTTP-01 challenge route；`sync_zones` 影响证书同步和漂移修复目标。`sync_zones` 为空数组时表示同步到所有在线 Agent。

删除证书：

```bash
curl -X DELETE "http://127.0.0.1:8080/v1/certificates/example.com" \
  -H "Authorization: Bearer changeme"
```

## 运维指标

Controller 暴露标准 `expvar` 指标：

```bash
curl "http://127.0.0.1:8080/metrics"
```

建议至少对这些指标配置告警：

- `agent_offline_total` 持续增加：有 Agent 心跳超时。
- `cert_drift_repair_failure_total` 持续增加：证书自动恢复失败。
- `cert_routing_prune_failure_total` 大于 0：zone 变更后旧 Agent 证书清理失败。
- `cert_drift_detected_total` 长时间增长但 `cert_drift_repair_total` 不增长：同步链路卡住。

## 数据库状态迁移

证书状态主字段为 `lifecycle_status`、`issue_status`、`sync_status`。开发落地阶段已清理旧 `status`、`renewing`、`renew_lock_at`、`cert_tasks` 等历史结构。

```bash
mysql < migrations/001_clean_schema.sql
```
