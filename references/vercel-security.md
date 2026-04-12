# Vercel Security Testing Reference

Vercel のインフラ・設定レベルのセキュリティ検査ガイド。
CLI/API で取得可能な項目と、Chrome MCP によるダッシュボード検査を組み合わせる。

## CLI による自動検査

### 環境変数の監査

```bash
# 全環境の環境変数を一覧
vercel env ls production
vercel env ls preview
vercel env ls development

# NEXT_PUBLIC_ プレフィックスで機密情報が露出していないか確認
vercel env ls production 2>/dev/null | grep -iE 'NEXT_PUBLIC_.*(SECRET|KEY|TOKEN|PASSWORD|CREDENTIAL)'
```

**検出すべきパターン**:
- `NEXT_PUBLIC_` に含まれる秘密鍵（`sk_`, `secret`, `password`）
- Production と Preview で同一の API キー（本番 DB への誤アクセスリスク）
- `sensitive` フラグが未設定の機密変数

### デプロイメント検査

```bash
# 最新デプロイの詳細確認
vercel inspect $(vercel ls --json 2>/dev/null | jq -r '.[0].url') 2>/dev/null

# デプロイメント一覧（不要な古いデプロイの確認）
vercel ls --json 2>/dev/null | jq '.[] | {url, state, created}'
```

### ドメイン・証明書

```bash
# ドメイン一覧
vercel domains ls

# SSL 証明書の確認
vercel certs ls
```

### vercel.json の静的解析

```bash
# vercel.json のセキュリティヘッダー確認
cat vercel.json 2>/dev/null | jq '.headers'

# public フラグ（ビルドログ・ソース露出）
cat vercel.json 2>/dev/null | jq '.public'
```

## vercel.json 必須セキュリティヘッダー

以下のヘッダーが設定されているか確認する:

| ヘッダー | 推奨値 | リスク |
|----------|--------|--------|
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains; preload` | HTTPS ダウングレード |
| `Content-Security-Policy` | `default-src 'self'` + 必要なソース | XSS |
| `X-Frame-Options` | `DENY` | クリックジャッキング |
| `X-Content-Type-Options` | `nosniff` | MIME スニッフィング |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | 情報漏洩 |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=()` | ブラウザ機能悪用 |

## Chrome MCP Dashboard Inspection

Dashboard-only settings that CLI cannot access. **Must run in main context** (not subagents).

### Prerequisites

1. Chrome is running and accessible by Chrome DevTools MCP
2. User is logged in to Vercel Dashboard
3. If not logged in, skip this section and note "Not Inspected — login required"

### URL Patterns

```
https://vercel.com/{team}/{project}/settings/deployment-protection
https://vercel.com/{team}/{project}/settings/security
https://vercel.com/{team}/{project}/firewall
https://vercel.com/{team}/{project}/settings/environment-variables
https://vercel.com/{team}/{project}/settings/domains
https://vercel.com/{team}/{project}/settings/functions
https://vercel.com/{team}/{project}/settings/git
```

### Step-by-Step Execution

#### 1. Deployment Protection

```
mcp__chrome-devtools__navigate_page(url: "https://vercel.com/{team}/{project}/settings/deployment-protection")
mcp__chrome-devtools__take_screenshot()  → capture evidence
mcp__chrome-devtools__take_snapshot()    → extract accessibility tree for setting values
```

**Checks**:
| Setting | Recommended | Remediation if Missing |
|---------|-------------|----------------------|
| Protection Scope | All Deployments | Dashboard → Deployment Protection → select "All Deployments" |
| Vercel Authentication | Enabled | Dashboard → Deployment Protection → toggle "Vercel Authentication" ON |
| Password Protection | Enabled for Preview | Dashboard → Deployment Protection → set password for Preview |
| Trusted IPs | Restricted to known IPs | Dashboard → Deployment Protection → add IP allowlist |

#### 2. Security Settings

```
mcp__chrome-devtools__navigate_page(url: "https://vercel.com/{team}/{project}/settings/security")
mcp__chrome-devtools__take_screenshot()  → capture evidence
mcp__chrome-devtools__take_snapshot()    → extract setting values
```

**Checks**:
| Setting | Recommended | Remediation if Missing |
|---------|-------------|----------------------|
| Attack Challenge Mode | Available | Dashboard → Security → verify toggle is accessible |
| Build Logs and Source Protection | Enabled | Dashboard → Security → toggle ON (hides `/_src`, `/_logs`) |
| Git Fork Protection | Enabled | Dashboard → Security → toggle ON (prevents env var leak from fork PRs) |
| Deployment Retention | Configured | Dashboard → Security → set appropriate retention period |

#### 3. Firewall (WAF)

```
mcp__chrome-devtools__navigate_page(url: "https://vercel.com/{team}/{project}/firewall")
mcp__chrome-devtools__take_screenshot()  → capture evidence
mcp__chrome-devtools__take_snapshot()    → extract rule list
```

**Checks**:
| Setting | Recommended | Remediation if Missing |
|---------|-------------|----------------------|
| Custom Rules | Rate limit on auth endpoints | Dashboard → Firewall → Add Rule → rate limit `/api/auth/*` |
| OWASP Managed Rulesets | Enabled | Dashboard → Firewall → Managed Rulesets → enable OWASP |
| IP Blocking | Block known malicious IPs | Dashboard → Firewall → IP Blocking → add rules |

#### 4. Git Settings

```
mcp__chrome-devtools__navigate_page(url: "https://vercel.com/{team}/{project}/settings/git")
mcp__chrome-devtools__take_screenshot()  → capture evidence
mcp__chrome-devtools__take_snapshot()    → extract setting values
```

**Checks**:
| Setting | Recommended | Remediation if Missing |
|---------|-------------|----------------------|
| Deploy Hooks | No unnecessary hooks exposed | Dashboard → Git → remove unused deploy hooks |
| Require Verified Commits | Enabled (GitHub only) | Dashboard → Git → toggle ON |

## よくある設定ミス

| 深刻度 | 設定ミス | 影響 |
|--------|----------|------|
| Critical | `NEXT_PUBLIC_` に秘密鍵 | クライアント JS で鍵が公開 |
| Critical | Preview にプロダクション API キー | Preview 経由で本番 DB にアクセス |
| High | セキュリティヘッダー未設定 | XSS、クリックジャッキング |
| High | Git Fork Protection 無効 | fork PR から環境変数漏洩 |
| High | Build Logs/Source Protection 無効 | ソースコードとビルドログが公開 |
| Medium | Preview の Deployment Protection なし | 未公開機能が外部公開 |
| Medium | Firewall ルールなし | レート制限なしで認証エンドポイント露出 |
| Medium | Deploy Hook の URL 漏洩 | 第三者がデプロイをトリガー可能 |
| Low | Deployment Retention 未設定 | 古いデプロイが不要に残存 |

## Vercel REST API による自動検査

```bash
# 環境変数の一覧取得（API 経由）
curl -s -H "Authorization: Bearer $VERCEL_TOKEN" \
  "https://api.vercel.com/v10/projects/$PROJECT_ID/env?teamId=$TEAM_ID" | \
  jq '.envs[] | {key, target, type}'

# Firewall 設定の確認
curl -s -H "Authorization: Bearer $VERCEL_TOKEN" \
  "https://api.vercel.com/v1/security/firewall/config?projectId=$PROJECT_ID&teamId=$TEAM_ID"
```
