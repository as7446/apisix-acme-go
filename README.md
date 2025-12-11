# apisix-acme-go

Go 实现的 APISIX 证书自动申请与续期服务，参考了项目 [`TMaize/apisix-acme`](https://github.com/TMaize/apisix-acme)。

## 功能特性

- **自动申请证书**：通过 ACME（默认 Let's Encrypt）为域名签发证书
- **自动续期**：定时扫描即将过期的证书并自动续期
- **多种验证方式**：支持 HTTP-01 和 DNS-01 两种 ACME 验证方式

## 快速开始

### 1. 安装

```bash
# 克隆项目
git clone https://github.com/as7446/apisix-acme-go.git
cd apisix-acme-go

# 编译
go build -o apisix-acme-go .

# 或直接运行
go run .
```

### 2. 配置

复制配置文件并修改：

```bash
cp config.example.yml config.yml
```

编辑 `config.yml`，至少需要配置：

- `apisix_admin_url`: APISIX Admin API 地址
- `apisix_admin_token`: APISIX Admin API Token
- `default_email`: ACME 账号邮箱
- `bearer_token`: API 鉴权 Token

### 3. 启动服务

```bash
./apisix-acme-go
```

服务默认监听 `:8080`

### 4. 创建证书任务

```bash
curl -X POST "http://127.0.0.1:8080/apisix_acme/task_create" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your-bearer-token" \
  -d '{
    "domain": "example.com",
    "email": "admin@example.com",
    "force": false
  }'
```

**请求参数说明：**

- `domain` (必填): 需要申请证书的域名
- `email` (可选): ACME 账号邮箱，未提供时使用配置中的 `default_email`
- `force` (可选): 是否强制重新申请，即使证书未过期（默认 `false`）

**响应示例：**

```json
{
  "code": 200,
  "message": "任务已提交，请稍候",
  "data": {
    "status": "created",
    "domain": "example.com"
  }
}
```

### 5. 查询任务状态

```bash
curl "http://127.0.0.1:8080/apisix_acme/task_status?domain=example.com" \
  -H "Authorization: Bearer your-bearer-token"
```

**响应示例：**

```json
{
  "code": 200,
  "data": {
    "status": "success",
    "domain": "example.com"
  }
}
```

#### 配置方式

**方式一：自动创建验证路由（推荐）**

在 `config.yml` 中启用 `challenge_route`：

```yaml
challenge_route:
  enable: true
  route_id: "apisix_acme_http01"
  hosts: []  # 可选，为空则匹配所有 Host
  upstream_nodes:
    - "127.0.0.1:8080"  # 本服务地址
  upstream_scheme: "http"
  priority: 2000  # 建议设置较高优先级，确保优先匹配
```

**方式二：手动创建验证路由**

如果不使用自动创建，可以手动在 APISIX 中创建路由：

```bash
curl -X PUT "http://127.0.0.1:9180/apisix/admin/routes/apisix_acme_http01" \
  -H "X-API-KEY: your-apisix-admin-token" \
  -H "Content-Type: application/json" \
  -d '{
    "uri": "/.well-known/acme-challenge/*",
    "methods": ["GET"],
    "upstream": {
      "type": "roundrobin",
      "nodes": {
        "127.0.0.1:8080": 1
      },
      "scheme": "http"
    },
    "priority": 2000
  }'
```

#### 配置方式

在 `config.yml` 中配置 DNS Provider：

```yaml
# DNS Provider 名称（lego 支持的 Provider）
acme_dns_provider: "cloudflare"

# DNS Provider 所需的环境变量
acme_dns_env:
  CF_DNS_API_TOKEN: "your-cloudflare-api-token"
```

#### 支持的 DNS Provider

项目使用 [lego](https://go-acme.github.io/lego/) 库，支持所有 lego 官方支持的 DNS Provider。常见 Provider 配置如下：

**Cloudflare**

```yaml
acme_dns_provider: "cloudflare"
acme_dns_env:
  CF_DNS_API_TOKEN: "your-cloudflare-api-token"
  # 或使用 API Key + Email
  # CF_API_EMAIL: "your-email@example.com"
  # CF_API_KEY: "your-api-key"
```

**DNSPod（腾讯云）**

```yaml
acme_dns_provider: "dnspod"
acme_dns_env:
  DNSPOD_API_KEY: "id,token"  # 格式：API ID,API Token
```

**更多 Provider**

查看 [lego DNS Providers 文档](https://go-acme.github.io/lego/dns/) 获取完整列表和配置说明。

#### 通配符证书

通配符证书（如 `*.example.com`）**必须**使用 DNS-01 验证，无法使用 HTTP-01。

**配置示例：**

```yaml
acme_dns_provider: "dnspod"
acme_dns_env:
  DNSPOD_API_KEY: "id,token"
```

**申请通配符证书：**

```bash
curl -X POST "http://127.0.0.1:8080/apisix_acme/task_create" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your-bearer-token" \
  -d '{
    "domain": "*.example.com",
    "email": "admin@example.com"
  }'
```

## API 接口

### 创建证书任务

```http
POST /apisix_acme/task_create
Authorization: Bearer <token>
Content-Type: application/json

{
  "domain": "example.com",
  "email": "admin@example.com",
  "force": false
}
```

### 查询任务状态

```http
GET /apisix_acme/task_status?domain=example.com
Authorization: Bearer <token>
```

### 工具页面

```http
GET /apisix_acme/tool.html
```

## 开发

### 构建

```bash
# 本地构建
go build -o apisix-acme-go .
```

### Docker 构建

```bash
# 构建多架构镜像
docker buildx build --platform linux/amd64,linux/arm64 -t apisix-acme-go:latest .
```

## 许可证

MIT License

## 参考

- 项目：[TMaize/apisix-acme](https://github.com/TMaize/apisix-acme)
- lego 文档：[go-acme.github.io/lego](https://go-acme.github.io/lego/)
- APISIX 文档：[apisix.apache.org](https://apisix.apache.org/)
