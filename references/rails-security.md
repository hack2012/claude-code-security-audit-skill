# Ruby on Rails Security Testing Reference

Ruby on Rails 固有の脆弱性パターンと検査ガイド。Brakeman ルール + OWASP Top 10 に基づく。

## SQL Injection

### リスク

ActiveRecord の `where` に文字列を直接渡す、`find_by_sql`、`execute` による raw SQL 実行で SQL Injection が発生する。Brakeman の SQL Injection 警告に対応。

### 検査パターン

```bash
# where に文字列結合（危険）
grep -rn --include='*.rb' -E '\.where\(\s*".*#\{' . | grep -v vendor | grep -v test

# where に文字列連結
grep -rn --include='*.rb' -E '\.where\(.*\+' . | grep -v vendor | grep -v test

# find_by_sql
grep -rn --include='*.rb' 'find_by_sql' . | grep -v vendor

# raw SQL 実行
grep -rn --include='*.rb' -E '(\.execute\(|connection\.exec|ActiveRecord::Base\.connection)' . | grep -v vendor

# order / group に文字列直接渡し
grep -rn --include='*.rb' -E '\.(order|group|pluck|select)\(.*#\{' . | grep -v vendor

# sanitize_sql の使用確認（安全対策）
grep -rn --include='*.rb' 'sanitize_sql' . | grep -v vendor

# Arel の使用確認（安全なクエリビルダ）
grep -rn --include='*.rb' 'Arel' . | grep -v vendor
```

## XSS (Cross-Site Scripting)

### リスク

Rails はデフォルトでビューの出力をエスケープするが、`html_safe`, `raw`, `<%== %>` でエスケープを無効化できる。

### 検査パターン

```bash
# html_safe の使用（Brakeman: CrossSiteScripting）
grep -rn --include='*.rb' --include='*.erb' '\.html_safe' . | grep -v vendor | grep -v test

# raw ヘルパーの使用
grep -rn --include='*.erb' '\braw\b' . | grep -v vendor

# <%== %> によるエスケープ無効化
grep -rn --include='*.erb' '<%==' . | grep -v vendor

# content_tag でのユーザー入力（属性インジェクション）
grep -rn --include='*.rb' --include='*.erb' 'content_tag.*params' . | grep -v vendor

# link_to の href にユーザー入力（javascript: スキーム）
grep -rn --include='*.rb' --include='*.erb' -E 'link_to.*params\[' . | grep -v vendor

# sanitize ヘルパーの使用確認
grep -rn --include='*.rb' --include='*.erb' '\bsanitize\b' . | grep -v vendor
```

## CSRF Protection

### 検査パターン

```bash
# protect_from_forgery の設定
grep -rn --include='*.rb' 'protect_from_forgery' . | grep -v vendor

# protect_from_forgery が ApplicationController にあるか
grep -A5 'class ApplicationController' app/controllers/application_controller.rb 2>/dev/null

# skip_forgery_protection / skip_before_action :verify_authenticity_token
grep -rn --include='*.rb' -E '(skip_forgery_protection|skip_before_action.*verify_authenticity_token)' . | grep -v vendor

# API モードの確認（CSRF が無効の場合がある）
grep -rn --include='*.rb' 'config\.api_only' . | grep -v vendor
```

## Mass Assignment

### リスク

Strong Parameters なしで `params` を直接 `create` / `update` に渡すと、攻撃者が任意のカラムを変更できる。

### 検査パターン

```bash
# permit なしの params 使用（Brakeman: MassAssignment）
grep -rn --include='*.rb' -E '\.(create|update|new|assign_attributes)\(params\b' . | grep -v vendor

# permit のワイルドカード（全属性許可は危険）
grep -rn --include='*.rb' 'permit!' . | grep -v vendor

# permit の内容確認（admin, role 等の特権属性）
grep -rn --include='*.rb' -A3 '\.permit\(' . | grep -v vendor

# Strong Parameters メソッドの定義
grep -rn --include='*.rb' -E 'def \w+_params' . | grep -v vendor
```

## Authentication

### 検査パターン

```bash
# Devise の設定
grep -rn --include='*.rb' 'devise' . | grep -v vendor | head -20

# has_secure_password の使用
grep -rn --include='*.rb' 'has_secure_password' . | grep -v vendor

# authenticate_user! フィルタ
grep -rn --include='*.rb' 'authenticate_user!' . | grep -v vendor

# before_action での認証チェック
grep -rn --include='*.rb' 'before_action.*authenticate' . | grep -v vendor

# skip_before_action での認証スキップ（要確認）
grep -rn --include='*.rb' 'skip_before_action.*authenticate' . | grep -v vendor

# パスワードの最小長設定
grep -rn --include='*.rb' -E '(password.*length|minimum.*password|validates.*password)' . | grep -v vendor
```

## Authorization

### 検査パターン

```bash
# Pundit の使用
grep -rn --include='*.rb' -E '(authorize|policy\(|PolicyScope)' . | grep -v vendor

# CanCanCan の使用
grep -rn --include='*.rb' -E '(can\?|authorize!|load_and_authorize|CanCan)' . | grep -v vendor

# 認可チェックなしのコントローラーアクション
for f in $(find app/controllers -name '*.rb' 2>/dev/null); do
  if ! grep -qE '(authorize|can\?|policy|before_action.*(admin|role|permission))' "$f" 2>/dev/null; then
    echo "NO AUTHZ: $f"
  fi
done

# current_user による所有者チェック（IDOR 防止）
grep -rn --include='*.rb' -E '(\.find\(params|\.find_by.*params)' app/controllers/ 2>/dev/null
# → current_user.xxx.find であるか確認
```

## File Upload

### 検査パターン

```bash
# ActiveStorage の使用
grep -rn --include='*.rb' 'has_one_attached\|has_many_attached' . | grep -v vendor

# CarrierWave の使用
grep -rn --include='*.rb' 'mount_uploader' . | grep -v vendor

# Shrine の使用
grep -rn --include='*.rb' 'include.*Shrine' . | grep -v vendor

# Content-Type バリデーション
grep -rn --include='*.rb' -E '(content_type|allowed_types|validate.*content)' . | grep -v vendor

# ファイルサイズ制限
grep -rn --include='*.rb' -E '(size.*limit|file_size|max.*size|validate.*size)' . | grep -v vendor

# パストラバーサル: ユーザー入力をファイル名に使用
grep -rn --include='*.rb' -E '(File\.join|Pathname\.new).*params' . | grep -v vendor
```

## Open Redirect

### リスク

`redirect_to` にユーザー入力を直接渡すと、外部サイトへのリダイレクトが可能。Brakeman の Redirect 警告に対応。

### 検査パターン

```bash
# redirect_to にパラメータ直接渡し（Brakeman: Redirect）
grep -rn --include='*.rb' -E 'redirect_to.*params\[' . | grep -v vendor

# redirect_back の fallback_location
grep -rn --include='*.rb' 'redirect_back' . | grep -v vendor

# allow_other_host オプション
grep -rn --include='*.rb' 'allow_other_host' . | grep -v vendor

# URL バリデーション
grep -rn --include='*.rb' -E '(URI\.parse|url_for|polymorphic_path)' . | grep -v vendor
```

## Session Security

### 検査パターン

```bash
# セッション設定
grep -rn --include='*.rb' -E '(session_store|cookie_store|session\[)' . | grep -v vendor

# Cookie 設定（Secure, HttpOnly, SameSite）
grep -rn --include='*.rb' -E '(secure:|httponly:|same_site:)' . | grep -v vendor

# config/initializers/session_store.rb
cat config/initializers/session_store.rb 2>/dev/null

# セッションの固定攻撃対策（reset_session）
grep -rn --include='*.rb' 'reset_session' . | grep -v vendor

# config.force_ssl（HTTPS 強制）
grep -rn --include='*.rb' 'force_ssl' . | grep -v vendor
```

## Secrets Management

### 検査パターン

```bash
# credentials.yml.enc の存在
ls -la config/credentials.yml.enc 2>/dev/null

# master.key の Git 追跡（危険）
git ls-files config/master.key 2>/dev/null

# .env ファイルの Git 追跡
git ls-files .env .env.local .env.production 2>/dev/null

# ハードコードされた秘密鍵
grep -rn --include='*.rb' -E '(secret_key|api_key|password)\s*=\s*["\x27]' . | grep -v vendor | grep -v test

# ENV の使用確認
grep -rn --include='*.rb' 'ENV\[' . | grep -v vendor | head -20

# Rails.application.credentials の使用
grep -rn --include='*.rb' 'Rails\.application\.credentials' . | grep -v vendor
```

## Command Injection

### リスク

`system`, バッククォート, `%x`, `Open3` にユーザー入力を渡すと任意コマンド実行が可能。Brakeman の Execute 警告に対応。

### 検査パターン

```bash
# system / exec コマンド（Brakeman: Execute）
grep -rn --include='*.rb' -E '\b(system|exec)\(.*params' . | grep -v vendor

# バッククォート実行
grep -rn --include='*.rb' '`.*#\{' . | grep -v vendor

# %x による実行
grep -rn --include='*.rb' '%x[({]' . | grep -v vendor

# Open3 による実行
grep -rn --include='*.rb' 'Open3\.' . | grep -v vendor

# Kernel.open（コマンドインジェクション可能）
grep -rn --include='*.rb' -E '(Kernel\.open|URI\.open)\(.*params' . | grep -v vendor

# send メソッド（メソッドインジェクション）
grep -rn --include='*.rb' -E '\.send\(.*params' . | grep -v vendor
```

## Deserialization

### リスク

`Marshal.load`, `YAML.load` による安全でないデシリアライズはリモートコード実行につながる。Brakeman の Deserialize 警告に対応。

### 検査パターン

```bash
# Marshal.load（Brakeman: Deserialize）
grep -rn --include='*.rb' 'Marshal\.load' . | grep -v vendor

# YAML.load（YAML.safe_load を使用すべき）
grep -rn --include='*.rb' 'YAML\.load\b' . | grep -v vendor | grep -v safe_load

# JSON.parse with create_additions（危険）
grep -rn --include='*.rb' 'create_additions' . | grep -v vendor

# Oj.load（Oj.safe_load を推奨）
grep -rn --include='*.rb' 'Oj\.load' . | grep -v vendor
```

## Dependency Security

### 検査パターン

```bash
# bundler-audit による脆弱性チェック
bundle-audit check --update 2>/dev/null || echo "bundler-audit not installed"

# Brakeman による静的解析
brakeman --no-pager 2>/dev/null || echo "brakeman not installed"

# Gemfile でバージョン固定されていない gem
grep -E "^gem\s+'" Gemfile 2>/dev/null | grep -v -E "(~>|>=|=\s*'[0-9])"

# Gemfile.lock の存在確認
ls -la Gemfile.lock 2>/dev/null

# Ruby バージョンの確認
ruby -v 2>/dev/null
grep -E '(ruby|RUBY_VERSION)' Gemfile 2>/dev/null
```

## Brakeman ルールマッピング

| Brakeman 警告 | 内容 | 深刻度 |
|---------------|------|--------|
| SQL Injection | where/order/group に文字列結合 | High |
| CrossSiteScripting | html_safe / raw の使用 | High |
| MassAssignment | params を直接 create/update に渡す | High |
| Execute | system / backtick にユーザー入力 | High |
| Redirect | redirect_to にユーザー入力 | Medium |
| Deserialize | Marshal.load / YAML.load | High |
| FileAccess | ファイル操作にユーザー入力 | High |
| ForgerySetting | CSRF 保護の欠如 | Medium |
| HeaderInjection | ヘッダーにユーザー入力 | Medium |
| DynamicRender | render にユーザー入力 | High |
| UnsafeReflection | constantize / send にユーザー入力 | High |

## Ruby on Rails セキュリティチェックリスト

- [ ] SQL クエリがプレースホルダまたは ActiveRecord メソッドを使用している
- [ ] `html_safe` / `raw` の使用が必要最小限で、入力がサニタイズ済み
- [ ] `protect_from_forgery` が ApplicationController に設定されている
- [ ] 全コントローラーで Strong Parameters が使用されている
- [ ] `permit!` が使用されていない
- [ ] 認証フィルタが全コントローラーに設定されている
- [ ] 認可チェック（Pundit / CanCanCan）が実装されている
- [ ] ファイルアップロードに Content-Type とサイズの制限がある
- [ ] `redirect_to` にユーザー入力が直接渡されていない
- [ ] セッション Cookie に Secure / HttpOnly フラグが設定されている
- [ ] `config.force_ssl = true` が本番環境で有効
- [ ] `config/master.key` が Git 追跡されていない
- [ ] `.env` ファイルが Git 追跡されていない
- [ ] `Marshal.load` / `YAML.load` が安全でないソースに使用されていない
- [ ] `system` / バッククォートにユーザー入力が渡されていない
- [ ] `bundler-audit` で既知脆弱性がゼロ
- [ ] Brakeman の High 以上の警告がゼロ
- [ ] Ruby / Rails バージョンがサポート期間内
