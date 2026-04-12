# Supabase Security Testing Reference

Supabase のバックエンド設定レベルのセキュリティ検査ガイド。
CLI/SQL で取得可能な項目と、Chrome MCP によるダッシュボード検査を組み合わせる。

## CLI による自動検査

### データベース Lint（最重要）

```bash
# public スキーマの lint 実行
supabase db lint --linked --schema public

# エラーレベル指定（CI/CD 向け）
supabase db lint --linked --fail-on warning
```

**Splinter Lint ルール（セキュリティ関連）**:

| コード | ルール名 | 深刻度 |
|--------|----------|--------|
| 0002 | Auth Users Exposed | Critical |
| 0006 | Multiple Permissive Policies | High |
| 0007 | Policy Exists RLS Disabled | Critical |
| 0008 | RLS Enabled No Policy | High |
| 0010 | Security Definer View | High |
| 0011 | Function Search Path Mutable | High |
| 0013 | RLS Disabled in Public | Critical |
| 0014 | Extension in Public | Medium |
| 0015 | RLS References user_metadata | High |

### SSL・ネットワーク検査

```bash
# SSL 強制の確認
supabase ssl-enforcement get --project-ref $PROJECT_REF

# ネットワーク制限の確認
supabase network-restrictions get --project-ref $PROJECT_REF

# ブルートフォースで BAN された IP の確認
supabase network-bans get --project-ref $PROJECT_REF
```

### Edge Functions

```bash
# 関数一覧
supabase functions list --project-ref $PROJECT_REF

# シークレット一覧
supabase secrets list --project-ref $PROJECT_REF
```

## SQL による詳細検査

### RLS 状態の確認（最重要）

```sql
-- RLS が無効なテーブル一覧（Critical）
SELECT n.nspname AS schema, c.relname AS table_name
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind = 'r'
  AND n.nspname = 'public'
  AND c.relrowsecurity = false
ORDER BY c.relname;

-- 全テーブルの RLS 状態
SELECT n.nspname AS schema, c.relname AS table_name,
  c.relrowsecurity AS rls_enabled, c.relforcerowsecurity AS rls_forced
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind = 'r' AND n.nspname = 'public'
ORDER BY c.relname;
```

### RLS ポリシーの検査

```sql
-- テーブルごとのポリシー確認
SELECT schemaname, tablename, policyname, permissive, roles, cmd,
  qual AS using_expression, with_check
FROM pg_policies WHERE schemaname = 'public'
ORDER BY tablename, policyname;

-- 過度に許容的なポリシー（USING (true)）の検出
SELECT schemaname, tablename, policyname, cmd, qual, with_check
FROM pg_policies
WHERE schemaname = 'public'
  AND (qual::text = 'true' OR with_check::text = 'true');

-- RLS 有効だがポリシーなしのテーブル
SELECT n.nspname, c.relname
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind = 'r' AND n.nspname = 'public' AND c.relrowsecurity = true
  AND c.relname NOT IN (SELECT tablename FROM pg_policies WHERE schemaname = 'public');
```

### 関数のセキュリティ検査

```sql
-- anon ロールが実行可能な関数
SELECT n.nspname, p.proname, p.prosecdef AS security_definer
FROM pg_proc p
JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE n.nspname = 'public'
  AND has_function_privilege('anon', p.oid, 'EXECUTE');

-- SECURITY DEFINER 関数（特権昇格リスク）
SELECT n.nspname, p.proname, r.rolname AS owner,
  pg_get_functiondef(p.oid) AS definition
FROM pg_proc p
JOIN pg_namespace n ON n.oid = p.pronamespace
JOIN pg_roles r ON r.oid = p.proowner
WHERE p.prosecdef = true
  AND n.nspname NOT IN ('pg_catalog', 'information_schema');
```

### 権限の検査

```sql
-- anon/authenticated の権限確認
SELECT grantee, table_schema, table_name, privilege_type
FROM information_schema.table_privileges
WHERE table_schema = 'public'
  AND grantee IN ('anon', 'authenticated')
ORDER BY table_name, grantee, privilege_type;
```

### Storage の検査

```sql
-- バケット一覧と公開状態
SELECT id, name, public, created_at FROM storage.buckets ORDER BY name;

-- Storage ポリシー
SELECT * FROM pg_policies WHERE schemaname = 'storage' ORDER BY tablename, policyname;
```

## Chrome MCP Dashboard Inspection

Dashboard-only settings that CLI/SQL cannot access. **Must run in main context** (not subagents).

### Prerequisites

1. Chrome is running and accessible by Chrome DevTools MCP
2. User is logged in to Supabase Dashboard
3. If not logged in, skip this section and note "Not Inspected — login required"

### URL Patterns

```
https://supabase.com/dashboard/project/{ref}/auth/providers
https://supabase.com/dashboard/project/{ref}/auth/url-configuration
https://supabase.com/dashboard/project/{ref}/auth/sessions
https://supabase.com/dashboard/project/{ref}/auth/rate-limits
https://supabase.com/dashboard/project/{ref}/auth/policies
https://supabase.com/dashboard/project/{ref}/settings/api
https://supabase.com/dashboard/project/{ref}/database/tables
https://supabase.com/dashboard/project/{ref}/database/security-advisor
https://supabase.com/dashboard/project/{ref}/storage/buckets
https://supabase.com/dashboard/project/{ref}/functions
```

### Step-by-Step Execution

#### 1. Auth Providers

```
mcp__chrome-devtools__navigate_page(url: "https://supabase.com/dashboard/project/{ref}/auth/providers")
mcp__chrome-devtools__take_screenshot()  → capture evidence
mcp__chrome-devtools__take_snapshot()    → extract provider toggle states
```

**Checks**:
| Setting | Recommended | Remediation if Missing |
|---------|-------------|----------------------|
| Email confirmation | Enabled | Dashboard → Auth → Providers → Email → toggle "Confirm email" ON |
| Unused OAuth providers | Disabled | Dashboard → Auth → Providers → disable unused providers |
| MFA (TOTP/Phone) | Enabled | Dashboard → Auth → MFA → enable TOTP or Phone factor |

#### 2. Session Settings

```
mcp__chrome-devtools__navigate_page(url: "https://supabase.com/dashboard/project/{ref}/auth/sessions")
mcp__chrome-devtools__take_screenshot()  → capture evidence
mcp__chrome-devtools__take_snapshot()    → extract session config values
```

**Checks**:
| Setting | Recommended | Remediation if Missing |
|---------|-------------|----------------------|
| Session expiry | Shorter than default (e.g., 1 hour) | Dashboard → Auth → Sessions → reduce JWT expiry |
| Inactivity timeout | Enabled | Dashboard → Auth → Sessions → set inactivity timeout |
| Refresh token reuse detection | Enabled | Dashboard → Auth → Sessions → toggle ON |

#### 3. Rate Limits

```
mcp__chrome-devtools__navigate_page(url: "https://supabase.com/dashboard/project/{ref}/auth/rate-limits")
mcp__chrome-devtools__take_screenshot()  → capture evidence
mcp__chrome-devtools__take_snapshot()    → extract rate limit values
```

**Checks**:
| Setting | Recommended | Remediation if Missing |
|---------|-------------|----------------------|
| Sign-up rate limit | Configured | Dashboard → Auth → Rate Limits → set sign-up limit |
| Sign-in rate limit | Configured | Dashboard → Auth → Rate Limits → set sign-in limit |
| Token refresh rate limit | Configured | Dashboard → Auth → Rate Limits → set token refresh limit |

#### 4. Security Advisor

```
mcp__chrome-devtools__navigate_page(url: "https://supabase.com/dashboard/project/{ref}/database/security-advisor")
mcp__chrome-devtools__take_screenshot()  → capture all findings
mcp__chrome-devtools__take_snapshot()    → extract finding details via accessibility tree
```

**Checks**:
| Setting | Recommended | Remediation if Missing |
|---------|-------------|----------------------|
| Critical findings | 0 items | Fix each Critical finding per Security Advisor guidance |
| High findings | 0 items | Fix each High finding per Security Advisor guidance |
| Lint warnings | Reviewed | Review and resolve or document accepted risks |

#### 5. API Settings

```
mcp__chrome-devtools__navigate_page(url: "https://supabase.com/dashboard/project/{ref}/settings/api")
mcp__chrome-devtools__take_screenshot()  → capture evidence
mcp__chrome-devtools__take_snapshot()    → extract API config
```

**Checks**:
| Setting | Recommended | Remediation if Missing |
|---------|-------------|----------------------|
| service_role key exposure | Not in client code | Verify via Grep (see static analysis section) |
| Data API | Disabled if not needed | Dashboard → Settings → API → toggle Data API OFF |
| JWT secret rotation | Rotated periodically | Dashboard → Settings → API → rotate JWT secret |

## よくある設定ミス

| 深刻度 | 設定ミス | 影響 |
|--------|----------|------|
| Critical | public テーブルで RLS 無効 | anon key で全データ読み書き可能 |
| Critical | service_role キーのクライアント露出 | RLS を完全バイパス |
| Critical | SSRF via http 拡張 | 任意 URL の取得が可能 |
| High | `USING (true)` の RLS ポリシー | 全行がアクセス可能 |
| High | Email 確認なし | 未確認メールでサインイン可能 |
| High | SECURITY DEFINER 関数の誤用 | 特権昇格 |
| High | RLS が user_metadata を参照 | ユーザーが自身で変更可能な値で認可判定 |
| Medium | Storage バケットのポリシー欠如 | 全ファイルが公開 |
| Medium | Realtime のフィルタなし | 不要なデータ漏洩 |
| Medium | public スキーマに拡張インストール | 攻撃面の拡大 |
| Low | カスタム SMTP 未設定 | 30 ユーザー/時間制限、配信性低下 |

## コードベースの静的解析

```bash
# service_role キーのクライアント露出検出
grep -rn --include='*.{ts,tsx,js,jsx}' \
  -E '(service_role|SUPABASE_SERVICE_ROLE|supabaseServiceRole)' . | \
  grep -v 'node_modules' | grep -v '.env'

# anon key のハードコード
grep -rn --include='*.{ts,tsx,js,jsx}' \
  -E 'eyJ[A-Za-z0-9_-]{20,}' . | grep -v 'node_modules'

# supabase-js の createClient で service_role を使用
grep -rn --include='*.{ts,tsx,js,jsx}' \
  -E 'createClient.*service_role' .
```
