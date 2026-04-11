# Secret Scanning Reference

Git 履歴、ビルド成果物、設定ファイルにおけるシークレット漏洩の検出ガイド。

## Git History（Git 履歴のスキャン）

### リスク

過去のコミットに含まれたシークレットは、`git log` や `git show` で復元可能。ファイルを削除しても Git 履歴からは消えない。

### 検査パターン

```bash
# gitleaks によるスキャン
gitleaks detect --source . --verbose 2>/dev/null | head -50

# trufflehog によるスキャン
trufflehog git file://. --only-verified 2>/dev/null | head -50

# git-secrets のインストール確認
git secrets --scan 2>/dev/null

# 直近のコミットでのシークレット検出
git log --diff-filter=A --name-only --pretty=format: -10 2>/dev/null | \
  grep -iE '\.(env|pem|key|p12|pfx|jks|keystore|credentials)$'

# .git/config にクレデンシャルが含まれていないか
grep -iE '(password|token|secret)' .git/config 2>/dev/null
```

## Common Secret Patterns（シークレットパターン）

### AWS

```bash
# AWS Access Key ID（AKIA で始まる 20 文字）
grep -rn -E 'AKIA[0-9A-Z]{16}' . --include='*.{ts,js,py,rb,go,java,yml,yaml,json,env,cfg,conf,toml}' \
  2>/dev/null | grep -v node_modules

# AWS Secret Access Key
grep -rn -E '['\''"][0-9a-zA-Z/+]{40}['\''"]' . \
  --include='*.{ts,js,py,rb,go,java,env}' 2>/dev/null | \
  grep -iE '(secret|aws)' | grep -v node_modules
```

### API トークン・キー

```bash
# GitHub Token（ghp_, gho_, ghs_, ghr_, github_pat_）
grep -rn -E '(ghp_[0-9a-zA-Z]{36}|gho_[0-9a-zA-Z]{36}|ghs_[0-9a-zA-Z]{36}|ghr_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82})' \
  . 2>/dev/null | grep -v node_modules

# Slack Token（xoxb-, xoxp-, xoxs-, xoxa-）
grep -rn -E 'xox[bpsa]-[0-9]{10,13}-[0-9a-zA-Z-]{20,}' \
  . 2>/dev/null | grep -v node_modules

# OpenAI API Key（sk-）
grep -rn -E 'sk-[0-9a-zA-Z]{20,}' . 2>/dev/null | grep -v node_modules

# Anthropic API Key（sk-ant-）
grep -rn -E 'sk-ant-[0-9a-zA-Z-]{20,}' . 2>/dev/null | grep -v node_modules

# Stripe Key（sk_live_, pk_live_）
grep -rn -E '(sk_live_|pk_live_|rk_live_)[0-9a-zA-Z]{20,}' \
  . 2>/dev/null | grep -v node_modules

# Google API Key
grep -rn -E 'AIza[0-9A-Za-z\\-_]{35}' . 2>/dev/null | grep -v node_modules

# SendGrid API Key
grep -rn -E 'SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}' \
  . 2>/dev/null | grep -v node_modules

# Twilio Account SID / Auth Token
grep -rn -E 'AC[a-z0-9]{32}' . 2>/dev/null | grep -v node_modules
```

### 秘密鍵・証明書

```bash
# RSA / EC / SSH 秘密鍵
grep -rn -E '-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----' \
  . 2>/dev/null | grep -v node_modules

# .pem / .key ファイルの検出
find . -name '*.pem' -o -name '*.key' -o -name '*.p12' -o -name '*.pfx' \
  -o -name '*.jks' 2>/dev/null | grep -v node_modules

# SSH 鍵ファイル
find . -name 'id_rsa' -o -name 'id_ed25519' -o -name 'id_ecdsa' \
  2>/dev/null | grep -v node_modules
```

### データベース接続文字列

```bash
# 接続文字列にパスワードが含まれているか
grep -rn -E '(postgres|mysql|mongodb|redis|amqp)://[^:]+:[^@]+@' \
  . 2>/dev/null | grep -v node_modules

# DATABASE_URL にパスワードが含まれているか
grep -rn 'DATABASE_URL' . 2>/dev/null | \
  grep -E '://[^:]+:[^@]+@' | grep -v node_modules
```

### 汎用パターン

```bash
# password / secret / token のハードコード
grep -rn --include='*.{ts,js,py,rb,go,java}' \
  -iE '(password|secret|token|api_key|apikey|api-key)\s*[:=]\s*['\''"][^'\''"{$]+['\''"]' \
  . 2>/dev/null | grep -v node_modules | grep -v -E '(test|spec|mock|example|placeholder)'

# JWT トークンのハードコード
grep -rn -E 'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}' \
  . 2>/dev/null | grep -v node_modules
```

## Build Artifacts（ビルド成果物）

### リスク

Docker レイヤー、ソースマップ、コンパイル済みアセットにシークレットが含まれる場合がある。

```bash
# Docker レイヤーでのシークレット検出
# docker history <image> --no-trunc 2>/dev/null | grep -iE '(secret|password|token|key)'

# ソースマップの存在確認（シークレットが含まれる可能性）
find . -name '*.map' -path '*/dist/*' -o -name '*.map' -path '*/build/*' \
  2>/dev/null | head -10

# ソースマップが本番で公開されていないか
grep -rn 'productionBrowserSourceMaps\|sourcemap\|source-map' \
  next.config.* webpack.config.* vite.config.* 2>/dev/null

# ビルド出力に .env が含まれていないか
find dist build out .next -name '.env*' 2>/dev/null
```

## Environment Files（環境ファイル）

### リスク

`.env` ファイルが Git にコミットされたり、公開ディレクトリに配置されると、全シークレットが漏洩する。

```bash
# .env ファイルの一覧
find . -name '.env*' -not -path '*/node_modules/*' 2>/dev/null

# .env ファイルが Git 追跡されているか（Critical）
git ls-files | grep -E '\.env'

# .gitignore に .env が含まれているか
grep -E '\.env' .gitignore 2>/dev/null

# .env ファイル内のシークレット一覧
for f in $(find . -name '.env*' -not -path '*/node_modules/*' 2>/dev/null); do
  echo "=== $f ==="
  grep -iE '(PASSWORD|SECRET|TOKEN|KEY|CREDENTIAL|PRIVATE)' "$f" 2>/dev/null | \
    sed 's/=.*/=***REDACTED***/'
done

# .env.example にデフォルト値が含まれていないか
grep -E '=.{8,}' .env.example .env.sample 2>/dev/null | \
  grep -v -E '(your-|example|placeholder|changeme|xxx)'
```

## Pre-commit Hooks（コミット前検出）

```bash
# pre-commit 設定の確認
cat .pre-commit-config.yaml 2>/dev/null | \
  grep -A 5 -E '(detect-secrets|gitleaks|trufflehog|git-secrets)'

# husky / lint-staged の設定確認
cat .husky/pre-commit 2>/dev/null
grep -A 5 'lint-staged' package.json 2>/dev/null

# git-secrets の設定確認
git config --get-all secrets.patterns 2>/dev/null
git config --get-all secrets.allowed 2>/dev/null
```

### 推奨 pre-commit 設定

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.0
    hooks:
      - id: gitleaks
  - repo: https://github.com/Yelp/detect-secrets
    rev: v1.4.0
    hooks:
      - id: detect-secrets
        args: ['--baseline', '.secrets.baseline']
```

## Secret Rotation（シークレットのローテーション）

### 漏洩時の対応手順

1. **即座に無効化**: 漏洩したシークレットを即座にローテーション
2. **影響範囲の確認**: `git log -p --all -S 'LEAKED_SECRET'` で漏洩範囲を特定
3. **Git 履歴からの除去**: `git filter-repo` または BFG Repo-Cleaner を使用
4. **全環境の更新**: CI/CD、デプロイ先、チームメンバーの環境を更新

```bash
# 漏洩したシークレットの Git 履歴検索
git log -p --all -S 'AKIA' 2>/dev/null | head -30

# BFG による除去（実行前にバックアップ必須）
# bfg --replace-text passwords.txt .

# git filter-repo による除去
# git filter-repo --invert-paths --path secrets.txt
```

## Secret Manager Integration

```bash
# AWS Secrets Manager の使用確認
grep -rn --include='*.{ts,js,py,rb,go}' \
  -E '(SecretsManager|secretsmanager|GetSecretValue)' . 2>/dev/null | \
  grep -v node_modules

# HashiCorp Vault の使用確認
grep -rn --include='*.{ts,js,py,rb,go,yml,yaml}' \
  -E '(vault\.|hashicorp|VAULT_ADDR|VAULT_TOKEN)' . 2>/dev/null | \
  grep -v node_modules

# 1Password CLI / Connect の使用確認
grep -rn --include='*.{ts,js,py,yml,yaml}' \
  -E '(1password|op://|OP_CONNECT|onepassword)' . 2>/dev/null

# Google Secret Manager の使用確認
grep -rn --include='*.{ts,js,py,go}' \
  -E '(secretmanager|SecretManagerServiceClient|google.*secret)' . 2>/dev/null | \
  grep -v node_modules

# Azure Key Vault の使用確認
grep -rn --include='*.{ts,js,py,go}' \
  -E '(KeyVaultClient|SecretClient|azure.*keyvault)' . 2>/dev/null | \
  grep -v node_modules
```

## gitleaks / trufflehog 設定

### gitleaks 設定例

```bash
# .gitleaks.toml の存在確認
cat .gitleaks.toml 2>/dev/null

# gitleaks 設定の推奨チェック
grep -E '(allowlist|rules|path)' .gitleaks.toml 2>/dev/null
```

### シークレットパターン一覧

| パターン名 | 正規表現 | 例 |
|-----------|---------|-----|
| AWS Access Key | `AKIA[0-9A-Z]{16}` | `AKIAIOSFODNN7EXAMPLE` |
| GitHub Token | `ghp_[0-9a-zA-Z]{36}` | `ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx` |
| Slack Token | `xox[bpsa]-[0-9]{10,}` | `xoxb-1234567890-abcdef` |
| OpenAI Key | `sk-[0-9a-zA-Z]{20,}` | `sk-xxxxxxxxxxxxxxxxxxxxxxxx` |
| Anthropic Key | `sk-ant-[0-9a-zA-Z-]{20,}` | `sk-ant-api03-xxxx` |
| Stripe Live Key | `sk_live_[0-9a-zA-Z]{20,}` | `sk_live_xxxxxxxxxxxx` |
| RSA Private Key | `-----BEGIN RSA PRIVATE KEY-----` | PEM 形式 |
| Connection String | `(postgres\|mysql)://.*:.*@` | `postgres://user:pass@host` |
| JWT | `eyJ[A-Za-z0-9_-]{10,}\.eyJ` | `eyJhbGciOiJIUzI1NiJ9.eyJ...` |
| Google API Key | `AIza[0-9A-Za-z\\-_]{35}` | `AIzaSyxxxxxxxxxxxxxxxxxxxxxxxxx` |
| SendGrid Key | `SG\.[0-9A-Za-z\-_]{22}\.` | `SG.xxxxxx.yyyyyyy` |

## よくある漏洩パターン

| 深刻度 | パターン | 影響 |
|--------|----------|------|
| Critical | AWS Access Key が Git にコミット | AWS アカウント乗っ取り |
| Critical | 秘密鍵（.pem, id_rsa）がリポジトリに存在 | サーバー不正アクセス |
| Critical | `.env.production` が Git 追跡されている | 全本番シークレット漏洩 |
| High | API キーがソースコードにハードコード | サービスの不正利用 |
| High | DB 接続文字列にパスワードが平文で記載 | データベースへの不正アクセス |
| High | Docker レイヤーにシークレットが残存 | コンテナからのシークレット抽出 |
| Medium | .env.example にデフォルトのシークレット値 | 推測可能なクレデンシャル |
| Medium | ソースマップが本番で公開 | ソースコード漏洩 |
| Low | テストコードにモックシークレットが不明確 | 本番シークレットとの混同 |

## シークレットスキャンチェックリスト

- [ ] gitleaks または trufflehog が CI/CD で実行されている
- [ ] pre-commit hook でシークレット検出が有効
- [ ] `.env` ファイルが `.gitignore` に含まれている
- [ ] `.env` ファイルが Git 追跡されていない（`git ls-files` で確認）
- [ ] AWS Access Key がソースコードに含まれていない
- [ ] API トークン・キーがハードコードされていない
- [ ] 秘密鍵ファイル（.pem, .key）がリポジトリに含まれていない
- [ ] DB 接続文字列が環境変数で管理されている
- [ ] Docker イメージにシークレットが焼き込まれていない
- [ ] ソースマップが本番環境で無効化されている
- [ ] Secret Manager（Vault, AWS SM, 1Password 等）が統合されている
- [ ] シークレットローテーションの手順が文書化されている
- [ ] `.env.example` にプレースホルダーのみが記載されている
