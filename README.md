# apisix-acme-go

Go 实现的 APISIX 证书自动申请与续期服务，参考了项目 [`TMaize/apisix-acme`](https://github.com/TMaize/apisix-acme)。

## 功能特性

- 自动申请证书（ACME，默认 Let's Encrypt）
- 自动续期（定时扫描即将过期的证书）
- 支持 HTTP-01 和 DNS-01 验证方式
- 自动同步 APISIX 证书状态

## 快速开始

### 安装

```bash
git clone https://github.com/as7446/apisix-acme-go.git
cd apisix-acme-go
go build -o apisix-acme-go .
```

### 配置

复制并编辑配置文件：

```bash
cp config.example.yml config.yml
```

必需配置项：

```yaml
apisix_admin_url: "http://127.0.0.1:9180"
apisix_admin_token: "your-apisix-admin-token"
default_email: "admin@example.com"
bearer_token: "your-api-token"
```

### 启动

```bash
./apisix-acme-go
```

服务默认监听 `:8080`

## 配置说明

### HTTP-01 验证（推荐）

自动创建验证路由：

```yaml
challenge_route:
  enable: true
  hosts: []  # 可选，为空则匹配所有 Host
  upstream_nodes:
    - "127.0.0.1:8080"  # 本服务地址
  upstream_scheme: "http"
  priority: 2000  # 建议设置较高优先级
```

### DNS-01 验证（通配符证书必需）

```yaml
acme_dns_provider: "cloudflare"  # 或 dnspod 等
acme_dns_env:
  CF_DNS_API_TOKEN: "your-token"
  # 或使用 API Key + Email
  # CF_API_EMAIL: "your-email"
  # CF_API_KEY: "your-key"
```

支持的 DNS Provider 见 [lego 文档](https://go-acme.github.io/lego/dns/)

### 其他配置

```yaml
renew_cron: "0 0 3 * * *"        # 续期检查时间（默认每天凌晨3点）
renew_before_days: 30            # 到期前多少天续期
sync_cron: "*/30 * * * * *"     # 同步 APISIX 证书状态
sync_mode: "compat"              # strict: 清理多余证书 | compat: 导入缺失证书
```

## API 接口

### 创建证书任务

```bash
curl -X POST "http://127.0.0.1:8080/apisix_acme/task_create" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your-token" \
  -d '{
    "domain": "example.com",
    "email": "admin@example.com",  # 可选，默认使用配置中的 default_email
    "force": false                  # 可选，是否强制重新申请
  }'
```

### 查询任务状态

```bash
curl "http://127.0.0.1:8080/apisix_acme/task_status?domain=example.com" \
  -H "Authorization: Bearer your-token"
```

### 查询证书信息

```bash
curl "http://127.0.0.1:8080/apisix_acme/cert_info?domain=example.com" \
  -H "Authorization: Bearer your-token"
```

### 删除证书

```bash
curl -X DELETE "http://127.0.0.1:8080/apisix_acme/cert_delete?domain=example.com" \
  -H "Authorization: Bearer your-token"
```

## 通配符证书

通配符证书（如 `*.example.com`）必须使用 DNS-01 验证：

```bash
curl -X POST "http://127.0.0.1:8080/apisix_acme/task_create" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your-token" \
  -d '{"domain": "*.example.com"}'
```

## 构建

```bash
# 本地构建
go build -o apisix-acme-go .

# Docker 多架构构建
docker buildx build --platform linux/amd64,linux/arm64 -t apisix-acme-go:latest .
```

## 参考

- 项目：[TMaize/apisix-acme](https://github.com/TMaize/apisix-acme)
- lego 文档：[go-acme.github.io/lego](https://go-acme.github.io/lego/)
- APISIX 文档：[apisix.apache.org](https://apisix.apache.org/)

## 许可证

MIT License
