# Web Security Testing Reference

OWASP WSTG + Top 10:2025 に基づく詳細検査ガイド。

## WSTG テストカテゴリ

### WSTG-INFO: 情報収集

- Web サーバーのフィンガープリント
- メタデータ・コメント内の情報漏洩
- エントリポイントの列挙
- アプリケーションマップの作成

### WSTG-CONF: 設定・デプロイメント

検査対象:
- セキュリティヘッダー（CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy）
- CORS 設定（ワイルドカードオリジンの検出）
- HTTP メソッド（不要な PUT/DELETE/TRACE の無効化）
- デフォルトクレデンシャル
- 管理画面の公開状態
- エラーページの情報露出
- .env / .git / backup ファイルの公開

```bash
# セキュリティヘッダー検査パターン
grep -rn --include='*.{ts,js,py,rb,go}' \
  -E '(helmet|SecurityHeaders|Content-Security-Policy|X-Frame-Options)' .

# CORS ワイルドカード検出
grep -rn --include='*.{ts,js,py,rb,go,json,yaml,yml}' \
  -E "(origin:\s*['\"]?\*|Access-Control-Allow-Origin.*\*|cors.*\*)" .
```

### WSTG-ATHN: 認証

検査対象:
- パスワードポリシー（最小長、複雑性）
- ブルートフォース対策（レート制限、アカウントロック）
- パスワードリセットフローの安全性
- セッション固定攻撃
- 多要素認証のバイパス
- JWT の検証不備（alg: none、鍵の露出、期限切れ未検証）

```bash
# JWT 検証パターン
grep -rn --include='*.{ts,js,py,rb,go}' \
  -E '(jwt\.(verify|decode|sign)|jsonwebtoken|PyJWT|jose)' .

# alg: none 許容の検出
grep -rn --include='*.{ts,js,py}' \
  -E '(algorithms.*none|ignoreExpiration.*true|verify.*false)' .
```

### WSTG-ATHZ: 認可

検査対象:
- IDOR（Insecure Direct Object Reference）
- 垂直権限昇格（一般ユーザー -> 管理者）
- 水平権限昇格（ユーザー A -> ユーザー B のリソース）
- パストラバーサル（`../` による制限外アクセス）
- API エンドポイントの認可チェック漏れ

```bash
# パラメータベースのオブジェクト参照検出
grep -rn --include='*.{ts,js,py,rb,go}' \
  -E '(params\.(id|userId|user_id)|req\.(params|query)\[.*(id|Id)\]|request\.(args|form)\[)' .

# 認可ミドルウェアの欠落確認（Express/Koa/Fastify）
grep -rn --include='*.{ts,js}' \
  -E '(router\.(get|post|put|patch|delete)|app\.(get|post|put|patch|delete))' . | \
  grep -v -E '(auth|middleware|guard|protect|verify|check)'
```

### WSTG-INPV: 入力検証

検査対象:
- SQL/NoSQL インジェクション
- コマンドインジェクション
- XSS（Reflected, Stored, DOM-based）
- SSTI（Server-Side Template Injection）
- SSRF（Server-Side Request Forgery）
- パラメータ汚染
- Mass Assignment

```bash
# SQL インジェクション危険パターン
grep -rn --include='*.{ts,js,py,rb,go}' \
  -E '(query\(.*\$\{|query\(.*\+.*req\.|execute\(.*%s|\.raw\(|\.exec\(.*\+)' .

# コマンドインジェクション
grep -rn --include='*.{ts,js,py,rb,go}' \
  -E '(child_process|exec\(|execSync|spawn|system\(|popen|subprocess|os\.system)' .

# eval / Function コンストラクタ
grep -rn --include='*.{ts,js,tsx,jsx}' \
  -E '(eval\(|new\s+Function\()' . | grep -v 'node_modules'

# DOM-based XSS パターン（innerHTML 等の直接 DOM 操作）
grep -rn --include='*.{ts,js,tsx,jsx}' \
  -E '(innerHTML|outerHTML|document\.write|v-html|bypassSecurityTrust)' .
```

### WSTG-SESS: セッション管理

検査対象:
- Cookie 属性（Secure, HttpOnly, SameSite, Path, Domain）
- セッション ID の十分なエントロピー
- セッションタイムアウト
- CSRF トークンの実装
- ログアウト時のセッション無効化

```bash
# Cookie 設定の確認
grep -rn --include='*.{ts,js,py,rb,go}' \
  -E '(setCookie|set-cookie|cookie\(|session\(|httpOnly|sameSite|secure:)' .

# CSRF トークン検出
grep -rn --include='*.{ts,js,py,rb,go,html}' \
  -E '(csrf|_token|authenticity_token|X-CSRF|xsrf)' .
```

### WSTG-CRYP: 暗号

検査対象:
- TLS 1.2 以上の使用
- 弱い暗号アルゴリズム（MD5, SHA1, DES, RC4）
- パスワードハッシュ（bcrypt/scrypt/Argon2 の使用）
- 暗号鍵のハードコード

```bash
# 弱い暗号アルゴリズム
grep -rn --include='*.{ts,js,py,rb,go,swift}' \
  -iE '(md5|sha1[^0-9]|des[^a-z]|rc4|createCipher\b)' . | \
  grep -v 'node_modules'

# パスワードハッシュの確認
grep -rn --include='*.{ts,js,py,rb,go}' \
  -iE '(bcrypt|scrypt|argon2|pbkdf2|hashpw)' .
```

### WSTG-APIT: API テスト

検査対象:
- 過剰なデータ露出（レスポンスに不要なフィールド）
- BOLA/BFLA（Broken Object/Function Level Authorization）
- レート制限の欠如
- GraphQL: イントロスペクション有効、ネスト攻撃
- API バージョニングと非推奨エンドポイント

```bash
# GraphQL イントロスペクション
grep -rn --include='*.{ts,js,py,rb,go}' \
  -E '(introspection|__schema|__type)' .

# レート制限の実装確認
grep -rn --include='*.{ts,js,py,rb,go}' \
  -iE '(rate.?limit|throttle|express-rate|slowDown|limiter)' .
```

## OWASP Top 10:2025 クイックリファレンス

| Rank | Category | 主な検出パターン |
|------|----------|------------------|
| A01 | Broken Access Control | 認可チェック欠落、IDOR、パストラバーサル |
| A02 | Security Misconfiguration | デフォルト設定、不要なサービス、エラー露出 |
| A03 | Supply Chain Failures | 既知脆弱性のある依存パッケージ |
| A04 | Cryptographic Failures | 弱い暗号、平文通信、鍵のハードコード |
| A05 | Injection | SQL/NoSQL/Command/XSS/SSTI |
| A06 | Insecure Design | 脅威モデリング欠如、ビジネスロジック欠陥 |
| A07 | Authentication Failures | 弱いパスワードポリシー、セッション管理不備 |
| A08 | Integrity Failures | CI/CD 改ざん、依存性検証欠如 |
| A09 | Logging Failures | 監査ログ欠如、機密データのログ出力 |
| A10 | Exception Handling | フェイルオープン、スタックトレース露出 |
