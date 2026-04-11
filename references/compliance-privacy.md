# Privacy & Security Framework Compliance Reference

プライバシー保護とセキュリティフレームワークに基づくコードレベル検査ガイド。
GDPR、CCPA、SOC 2 Type II、ISO 27001 の主要要件をカバーする。

## GDPR (General Data Protection Regulation)

EU 居住者の個人データを処理するシステムに適用。プライバシー・バイ・デザインの原則に基づく。

### データ主体の権利（Data Subject Rights）

削除権（Right to Erasure）、ポータビリティ権、アクセス権の実装を検査する。

```bash
# データ削除機能の実装確認
grep -rn --include='*.{ts,js,py,rb,go,java}' \
  -iE '(deleteUser|delete.?account|erase|purge|forget.?me|right.?to.?erasure|gdpr.?delete)' .

# データエクスポート / ポータビリティ機能
grep -rn --include='*.{ts,js,py,rb,go,java}' \
  -iE '(export.?data|download.?data|portability|data.?export|user.?data.?download)' .

# データアクセスリクエスト（SAR: Subject Access Request）
grep -rn --include='*.{ts,js,py,rb,go,java}' \
  -iE '(subject.?access|data.?access.?request|sar|dsar|get.?my.?data)' .

# 論理削除 vs 物理削除の確認
grep -rn --include='*.{ts,js,py,rb,go,java}' \
  -iE '(soft.?delete|is.?deleted|deleted.?at|paranoid|withDeleted)' .
```

### 同意管理（Consent Management）

データ処理の同意取得・撤回メカニズムを検査する。

```bash
# 同意フラグ・同意管理の実装
grep -rn --include='*.{ts,js,py,rb,go,java,tsx,jsx}' \
  -iE '(consent|opt.?in|opt.?out|cookie.?consent|cookie.?banner|accept.?cookies)' .

# 同意のタイムスタンプ記録
grep -rn --include='*.{ts,js,py,rb,go,java}' \
  -iE '(consent.?date|consent.?timestamp|consented.?at|consent.?version)' .

# 同意なしのトラッキング（違反の可能性）
grep -rn --include='*.{ts,js,tsx,jsx,html}' \
  -iE '(gtag|ga\(|analytics|fbq|_paq|hotjar|segment\.track)' . | \
  grep -v node_modules | head -20
```

### データ最小化と Privacy by Design

不必要なデータ収集の検出、データ保護設計を確認する。

```bash
# フォームフィールドの過剰収集（特別カテゴリデータ）
grep -rn --include='*.{ts,js,tsx,jsx,html}' \
  -iE '(gender|ethnicity|race|religion|political|sexual|biometric|genetic)' . | \
  grep -iE '(input|field|form|register|signup)'

# データ保持期間の実装
grep -rn --include='*.{ts,js,py,rb,go,java}' \
  -iE '(retention|expiry|expire|ttl|purge.?after|delete.?after|data.?lifecycle)' .

# 匿名化・仮名化の実装
grep -rn --include='*.{ts,js,py,rb,go,java}' \
  -iE '(anonymize|pseudonymize|de.?identify|tokenize|hash.?pii)' .
```

### GDPR コード検出パターンまとめ

| 検出対象 | パターン | 深刻度 |
|----------|----------|--------|
| データ削除機能の欠如 | `deleteUser` 等の不在 | Critical |
| 同意なしのトラッキング | consent チェックなしの analytics | Critical |
| 同意タイムスタンプ未記録 | `consentDate` の不在 | High |
| 論理削除のみ（物理削除なし） | `softDelete` のみ | High |
| データ保持期間未設定 | `retention` 関連コードの不在 | High |
| 過剰なデータ収集 | 不要な PII フィールド | Medium |
| エクスポート機能の欠如 | `exportData` 等の不在 | High |

---

## CCPA (California Consumer Privacy Act)

カリフォルニア州居住者の個人情報を扱うシステムに適用。

### 消費者の権利と Do Not Sell

オプトアウト、データ削除、「Do Not Sell」メカニズムの実装を確認。

```bash
# オプトアウト / Do Not Sell 機能の実装
grep -rn --include='*.{ts,js,py,rb,go,java,tsx,jsx}' \
  -iE '(opt.?out|do.?not.?sell|do.?not.?share|ccpa|privacy.?choice)' .

# データ削除リクエスト機能
grep -rn --include='*.{ts,js,py,rb,go,java}' \
  -iE '(delete.?request|deletion.?request|ccpa.?delete|consumer.?delete)' .

# サードパーティへのデータ共有
grep -rn --include='*.{ts,js,py,rb,go,java}' \
  -iE '(share.?data|sell.?data|third.?party|data.?broker|data.?partner)' .

# GPC（Global Privacy Control）ヘッダーの対応
grep -rn --include='*.{ts,js,py,rb,go,java}' \
  -iE '(globalPrivacyControl|Sec-GPC|gpc.?header|navigator\.globalPrivacyControl)' .

# プライバシーポリシーページ
grep -rn --include='*.{ts,js,tsx,jsx,html}' \
  -iE '(privacy.?policy|privacy.?notice|privacy.?settings)' .
```

### CCPA コード検出パターンまとめ

| 検出対象 | パターン | 深刻度 |
|----------|----------|--------|
| オプトアウト機能の欠如 | `opt-out` 関連コードの不在 | Critical |
| 「Do Not Sell」リンクの欠如 | `doNotSell` の不在 | Critical |
| GPC ヘッダー未対応 | `Sec-GPC` 処理の不在 | High |
| データ削除機能の欠如 | 削除リクエスト処理の不在 | High |
| サードパーティ共有の未管理 | 共有先の制御なし | High |

---

## SOC 2 Type II

5 つの Trust Services Criteria（TSC）に基づくコードレベルの統制を検査する。

### Security（セキュリティ）

```bash
# 認証・認可の実装確認
grep -rn --include='*.{ts,js,py,rb,go,java}' \
  -iE '(authenticate|login|signIn|verifyToken|authorize|permission|guard|canActivate)' .

# セッション管理
grep -rn --include='*.{ts,js,py,rb,go,java}' \
  -iE '(session.?timeout|idle.?timeout|max.?age|expires.?in|token.?expiry)' .

# 入力バリデーション
grep -rn --include='*.{ts,js,py,rb,go,java}' \
  -iE '(validate|sanitize|escape|parameterize|prepared.?statement)' .
```

### Availability（可用性）

```bash
# ヘルスチェック・リトライの実装
grep -rn --include='*.{ts,js,py,rb,go,java}' \
  -iE '(health.?check|healthCheck|readiness|liveness|retry|circuit.?breaker|fallback)' .

# バックアップ・リストア関連
grep -rn --include='*.{ts,js,py,rb,go,java,yaml,yml,json}' \
  -iE '(backup|restore|disaster.?recovery|failover|replication)' .
```

### Processing Integrity（処理の完全性）

```bash
# スキーマバリデーション
grep -rn --include='*.{ts,js,py,rb,go,java}' \
  -iE '(schema.?validation|zod|joi|yup|class-validator|marshmallow|pydantic)' .

# トランザクション管理・整合性検証
grep -rn --include='*.{ts,js,py,rb,go,java}' \
  -iE '(transaction|commit|rollback|atomic|checksum|integrity|hmac)' .
```

### Confidentiality / Privacy（機密性・プライバシー）

```bash
# 暗号化・シークレット管理
grep -rn --include='*.{ts,js,py,rb,go,java}' \
  -iE '(encrypt|decrypt|cipher|aes|vault|secret.?manager|aws.?secrets|key.?vault)' . | \
  grep -v node_modules | head -20

# PII フィールドの検出
grep -rn --include='*.{ts,js,py,rb,go,java}' \
  -iE '(email|phone|address|firstName|first_name|lastName|last_name|dateOfBirth|ssn|passport)' . | \
  grep -v node_modules | grep -v '\.test\.' | head -20

# PII のマスキング・リダクション
grep -rn --include='*.{ts,js,py,rb,go,java}' \
  -iE '(mask|redact|encrypt|hash).*(email|phone|name|address|ssn)' .
```

### SOC 2 コード検出パターンまとめ

| TSC | 検出対象 | パターン | 深刻度 |
|-----|----------|----------|--------|
| Security | 認証の欠如 | `authenticate` 関連の不在 | Critical |
| Security | 認可の欠如 | `authorize` 関連の不在 | Critical |
| Security | 入力検証の欠如 | `validate` 関連の不在 | High |
| Availability | ヘルスチェック未実装 | `healthCheck` の不在 | Medium |
| Integrity | スキーマ検証の欠如 | `zod`/`joi` 等の不在 | High |
| Confidentiality | 暗号化未実装 | `encrypt` 関連の不在 | High |
| Privacy | PII マスキングの欠如 | `mask`/`redact` の不在 | High |

---

## ISO 27001

情報セキュリティマネジメントシステム（ISMS）の Annex A コントロールに基づくコードレベル検査。

### A.8 資産管理 / A.9 アクセス制御

```bash
# データ分類レベルの実装
grep -rn --include='*.{ts,js,py,rb,go,java}' \
  -iE '(data.?classification|security.?level|confidential|restricted|top.?secret)' .

# アクセス制御ポリシー・最小権限
grep -rn --include='*.{ts,js,py,rb,go,java}' \
  -iE '(access.?control|acl|rbac|abac|policy.?engine|least.?privilege|scoped.?token)' .

# 特権アクセスの管理
grep -rn --include='*.{ts,js,py,rb,go,java}' \
  -iE '(privileged|sudo|root|admin.?access|elevated|superuser|impersonate)' .

# パスワードハッシュの実装
grep -rn --include='*.{ts,js,py,rb,go,java}' \
  -iE '(bcrypt|scrypt|argon2|pbkdf2|password.?hash|password.?policy)' .
```

### A.10 暗号（Cryptography）

```bash
# 暗号アルゴリズムの使用確認
grep -rn --include='*.{ts,js,py,rb,go,java}' \
  -iE '(aes|rsa|ecdsa|ed25519|chacha20|sha256|sha512)' . | grep -v node_modules

# 弱い暗号アルゴリズムの検出
grep -rn --include='*.{ts,js,py,rb,go,java}' \
  -iE '(md5|sha1[^0-9]|des[^a-z]|rc4|blowfish|createCipher\b)' . | grep -v node_modules

# 暗号鍵のハードコード検出
grep -rn --include='*.{ts,js,py,rb,go,java}' \
  -iE '(PRIVATE_KEY|SECRET_KEY|ENCRYPTION_KEY|API_KEY)\s*[:=]\s*["\x27]' . | \
  grep -v node_modules | grep -v '\.env\.example'

# 鍵管理サービスの使用
grep -rn --include='*.{ts,js,py,rb,go,java}' \
  -iE '(kms|key.?management|key.?rotation|key.?vault|hsm)' .
```

### A.12 運用セキュリティ / A.14 システム開発セキュリティ

```bash
# 構造化ロギングの実装
grep -rn --include='*.{ts,js,py,rb,go,java}' \
  -iE '(winston|pino|bunyan|log4j|logback|slog|zerolog|structlog)' .

# セキュリティイベントのログ
grep -rn --include='*.{ts,js,py,rb,go,java}' \
  -iE '(security.?event|auth.?log|login.?log|access.?denied|unauthorized)' .

# ファイルアップロードの検証
grep -rn --include='*.{ts,js,py,rb,go,java}' \
  -iE '(file.?type|mime.?type|magic.?bytes|virus.?scan|malware.?scan|clamav)' .

# CI/CD セキュリティスキャン
cat .github/workflows/*.yml 2>/dev/null | \
  grep -iE '(npm audit|snyk|dependabot|codeql|semgrep|sonarqube|trivy)'
```

### ISO 27001 コード検出パターンまとめ

| Annex A | 検出対象 | パターン | 深刻度 |
|---------|----------|----------|--------|
| A.8 | データ分類の欠如 | `classification` の不在 | Medium |
| A.9 | アクセス制御の欠如 | `rbac`/`acl` の不在 | High |
| A.9 | 特権アクセスの未管理 | `admin` のハードコード | High |
| A.10 | 弱い暗号アルゴリズム | `MD5`/`SHA1`/`DES` | High |
| A.10 | 暗号鍵のハードコード | `SECRET_KEY = "..."` | Critical |
| A.10 | 鍵管理の欠如 | `KMS` 関連の不在 | High |
| A.12 | 構造化ログの欠如 | logging ライブラリの不在 | Medium |
| A.14 | セキュリティスキャンの欠如 | SAST/DAST の不在 | High |

---

## 統合コンプライアンスチェックリスト

### GDPR チェックリスト

- [ ] データ削除機能（Right to Erasure）が実装されている
- [ ] データエクスポート機能（Right to Portability）が実装されている
- [ ] データアクセスリクエスト（SAR）の処理が実装されている
- [ ] 同意取得メカニズムが実装されている
- [ ] 同意の撤回が可能である
- [ ] 同意取得のタイムスタンプが記録されている
- [ ] 同意前にトラッキングが開始されていない
- [ ] データ保持期間が定義・実装されている
- [ ] データ最小化の原則に従い、必要最小限のデータのみ収集している
- [ ] PII の匿名化・仮名化が適切に実装されている

### CCPA チェックリスト

- [ ] 「Do Not Sell or Share My Personal Information」リンクが実装されている
- [ ] オプトアウトメカニズムが機能している
- [ ] GPC（Global Privacy Control）ヘッダーに対応している
- [ ] データ削除リクエストの処理が実装されている
- [ ] プライバシーポリシーが適切にリンクされている
- [ ] サードパーティへのデータ共有が管理されている

### SOC 2 Type II チェックリスト

- [ ] 認証メカニズムが全エンドポイントに実装されている
- [ ] 認可チェックがリソースレベルで実装されている
- [ ] セッションタイムアウトが適切に設定されている
- [ ] 入力バリデーションが全ユーザー入力に適用されている
- [ ] ヘルスチェックエンドポイントが実装されている
- [ ] スキーマバリデーションが使用されている
- [ ] トランザクション管理が適切に実装されている
- [ ] 機密データが暗号化されている
- [ ] シークレット管理ツールが使用されている
- [ ] PII のマスキング・リダクションが実装されている
- [ ] 監査ログが適切に記録されている

### ISO 27001 チェックリスト

- [ ] 情報資産の分類が実装されている
- [ ] アクセス制御ポリシーが実装されている（RBAC/ABAC）
- [ ] 最小権限の原則が適用されている
- [ ] 特権アクセスが適切に管理されている
- [ ] 強い暗号アルゴリズムのみ使用されている（AES-256, SHA-256 以上）
- [ ] 暗号鍵がコードにハードコードされていない
- [ ] 鍵管理サービス（KMS）が使用されている
- [ ] 構造化ロギングが実装されている
- [ ] セキュリティイベントが記録されている
- [ ] CI/CD パイプラインにセキュリティスキャンが含まれている
- [ ] 依存関係の脆弱性スキャンが自動化されている
