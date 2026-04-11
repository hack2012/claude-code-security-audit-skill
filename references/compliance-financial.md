# Financial & Healthcare Compliance Reference

金融・医療分野のコンプライアンス要件に基づくコードレベル検査ガイド。
PCI-DSS v4.0、HIPAA、SOX の主要要件をカバーする。

## PCI-DSS v4.0 (Payment Card Industry Data Security Standard)

カード会員データを扱うシステムに適用される。コードレベルで検出可能な違反パターンに焦点を当てる。

### Requirement 3: カード会員データの保護

PAN（Primary Account Number）は保存時に暗号化またはマスキングが必要。表示時は先頭 6 桁 / 末尾 4 桁のみ許可。

```bash
# クレジットカード番号パターンの検出（コード内のハードコード）
grep -rn --include='*.{ts,js,py,rb,go,java,php}' \
  -E '[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}' . | grep -v node_modules

# PAN の平文保存パターン
grep -rn --include='*.{ts,js,py,rb,go,java}' \
  -iE '(cardNumber|card_number|pan|creditCard|credit_card|ccNumber|cc_number)' . | \
  grep -v node_modules

# PAN をログ出力している箇所
grep -rn --include='*.{ts,js,py,rb,go,java}' \
  -iE '(console\.(log|info|warn|error)|logger\.|logging\.|log\.).*card' . | \
  grep -v node_modules

# PAN マスキング実装の確認
grep -rn --include='*.{ts,js,py,rb,go,java}' \
  -iE '(mask|truncate|redact).*card' .

# 暗号化ライブラリの使用確認
grep -rn --include='*.{ts,js,py,rb,go,java}' \
  -iE '(aes-256|AES_256|aes256|encrypt.*card|card.*encrypt)' .
```

### Requirement 4: 通信経路の暗号化

カード会員データの伝送は TLS 1.2 以上で暗号化する。

```bash
# HTTP（非 HTTPS）通信の検出
grep -rn --include='*.{ts,js,py,rb,go,java}' \
  -E "http://[^l][^o][^c][^a][^l]" . | grep -v node_modules | grep -v '\.test\.'

# TLS バージョン指定の確認
grep -rn --include='*.{ts,js,py,rb,go,java}' \
  -iE '(TLSv1_0|TLSv1_1|SSLv3|ssl_version|minVersion.*TLS)' .

# SSL 証明書検証の無効化
grep -rn --include='*.{ts,js,py,rb,go,java}' \
  -iE '(rejectUnauthorized.*false|verify_ssl.*false|VERIFY_NONE|InsecureSkipVerify|NODE_TLS_REJECT_UNAUTHORIZED)' .
```

### Requirement 6: セキュアなシステム開発

脆弱性管理とセキュアコーディングの実践が必須。

```bash
# 既知の脆弱性チェック
npm audit --json 2>/dev/null | head -50

# セキュリティ関連の TODO/FIXME
grep -rn --include='*.{ts,js,py,rb,go,java}' \
  -iE '(TODO|FIXME|HACK|XXX).*(security|vuln|auth|encrypt|password|token)' .

# デバッグコードの残存
grep -rn --include='*.{ts,js,py,rb,go,java}' \
  -iE '(debugger|console\.debug|DEBUG\s*=\s*true|DEBUG_MODE)' . | grep -v node_modules
```

### Requirement 8: 認証とアクセス管理

MFA の実装とパスワードポリシーの遵守が必要。

```bash
# パスワードポリシーの実装確認
grep -rn --include='*.{ts,js,py,rb,go,java}' \
  -iE '(password.*length|minLength.*password|passwordPolicy|password.*regex|password.*pattern)' .

# MFA / 2FA 実装の確認
grep -rn --include='*.{ts,js,py,rb,go,java}' \
  -iE '(mfa|2fa|two.?factor|totp|authenticator|otp)' .

# デフォルトパスワード・ハードコードパスワード
grep -rn --include='*.{ts,js,py,rb,go,java}' \
  -iE "(password\s*[:=]\s*['\"][^'\"]+['\"]|default.*password|admin.*password)" . | \
  grep -v node_modules | grep -v '\.test\.' | grep -v '\.spec\.'
```

### Requirement 10: 監査ログ

カード会員データへの全アクセスのログ記録が必要。

```bash
# 監査ログ実装の確認
grep -rn --include='*.{ts,js,py,rb,go,java}' \
  -iE '(audit.?log|access.?log|activity.?log|event.?log)' .

# ログに機密データが含まれていないか
grep -rn --include='*.{ts,js,py,rb,go,java}' \
  -iE '(log|logger|logging).*(password|secret|token|key|card|ssn|cvv)' . | \
  grep -v node_modules

# ログの改ざん防止（追記のみ、署名付き等）
grep -rn --include='*.{ts,js,py,rb,go,java}' \
  -iE '(immutable|append.?only|tamper.?proof|log.*integrity)' .
```

### PCI-DSS コード検出パターンまとめ

| 検出対象 | パターン | 深刻度 |
|----------|----------|--------|
| PAN のハードコード | `[0-9]{4}[- ]?...` 16 桁パターン | Critical |
| PAN のログ出力 | `log.*card` | Critical |
| CVV の保存 | `cvv`, `cvc`, `securityCode` の DB 保存 | Critical |
| HTTP 通信 | `http://` (localhost 以外) | High |
| SSL 検証無効化 | `rejectUnauthorized: false` | High |
| デフォルトパスワード | ハードコードされたクレデンシャル | High |
| 監査ログ欠如 | `audit` 関連コードの不在 | Medium |

---

## HIPAA (Health Insurance Portability and Accountability Act)

PHI（Protected Health Information）を扱うシステムに適用。

### PHI の識別と保護

コード内で PHI に該当するデータフィールドを検出する。

```bash
# PHI 関連フィールドの検出
grep -rn --include='*.{ts,js,py,rb,go,java}' \
  -iE '(patient|diagnosis|medical|health|treatment|prescription|medication|insurance|provider|ssn|social_security|dateOfBirth|dob|mrn|medical_record)' . | \
  grep -v node_modules

# ICD/CPT コード（医療コード）の検出
grep -rn --include='*.{ts,js,py,rb,go,java}' \
  -iE '(icd.?code|cpt.?code|diagnosis.?code|procedure.?code)' .

# SSN パターンの検出
grep -rn --include='*.{ts,js,py,rb,go,java}' \
  -E '[0-9]{3}-[0-9]{2}-[0-9]{4}' . | grep -v node_modules
```

### 暗号化: 保存時と通信時

PHI は保存時（at rest）と通信時（in transit）の両方で暗号化が推奨。

```bash
# データベース暗号化の設定確認
grep -rn --include='*.{ts,js,py,rb,go,java,json,yaml,yml}' \
  -iE '(encrypt.*column|column.*encrypt|field.*encrypt|pgcrypto|TDE|transparent.*encrypt)' .

# フィールドレベル暗号化の実装
grep -rn --include='*.{ts,js,py,rb,go,java}' \
  -iE '(encrypt.*patient|encrypt.*phi|encrypt.*health|encrypt.*medical)' .

# 暗号化キーの管理
grep -rn --include='*.{ts,js,py,rb,go,java}' \
  -iE '(KMS|key.?management|key.?vault|aws.?kms|azure.?keyvault|ENCRYPTION_KEY)' .
```

### アクセス制御と監査ログ

RBAC（ロールベースアクセス制御）と全アクセスの監査記録が必要。

```bash
# ロールベースアクセス制御の実装確認
grep -rn --include='*.{ts,js,py,rb,go,java}' \
  -iE '(role|permission|rbac|access.?control|authorize|canAccess|hasPermission|checkRole)' .

# PHI アクセスの監査ログ
grep -rn --include='*.{ts,js,py,rb,go,java}' \
  -iE '(audit|access.?log).*(patient|phi|medical|health)' .

# ログからの PHI 除外（ログサニタイゼーション）
grep -rn --include='*.{ts,js,py,rb,go,java}' \
  -iE '(sanitize|redact|mask|filter).*(log|phi|patient)' .
```

### Minimum Necessary / BAA 準拠

PHI へのアクセスは業務上必要な最小限に制限。サードパーティへの PHI 送信も確認する。

```bash
# SELECT * の使用（Minimum Necessary 違反の可能性）
grep -rn --include='*.{ts,js,py,rb,go,java}' \
  -iE '(SELECT\s+\*|findAll|find\(\)|\.all\(\))' . | \
  grep -iE '(patient|medical|health|record)'

# サードパーティ API / Analytics での PHI 漏洩
grep -rn --include='*.{ts,js,py,rb,go,java}' \
  -iE '(fetch|axios|http|analytics|tracking|gtag|segment)' . | \
  grep -iE '(patient|medical|health|diagnosis|ssn)'
```

### HIPAA コード検出パターンまとめ

| 検出対象 | パターン | 深刻度 |
|----------|----------|--------|
| PHI のログ出力 | `log.*(patient|diagnosis|ssn)` | Critical |
| PHI の平文保存 | PHI フィールドに暗号化なし | Critical |
| PHI の暗号化未実施 | 暗号化関連コードの不在 | High |
| SELECT * で PHI 取得 | `SELECT *` + 医療テーブル | High |
| サードパーティへの PHI 送信 | API 呼び出し + PHI データ | High |
| RBAC 未実装 | ロール/権限チェックの不在 | High |
| 監査ログ未実装 | PHI アクセスログの不在 | High |
| SSN のハードコード | `[0-9]{3}-[0-9]{2}-[0-9]{4}` | Critical |
| Analytics での PHI 漏洩 | tracking + PHI フィールド | Medium |

---

## SOX (Sarbanes-Oxley Act)

上場企業の財務報告に関連するシステムに適用。IT 統制（ITGC）の観点からコードを検査する。

### 変更管理

コードの変更には適切なレビューと承認が必要。

```bash
# マージ制限の設定確認（GitHub）
cat .github/CODEOWNERS 2>/dev/null
cat .github/branch-protection.json 2>/dev/null

# PR レビュー必須設定の確認
gh api repos/{owner}/{repo}/branches/main/protection 2>/dev/null | \
  grep -E '(required_approving_review_count|required_pull_request_reviews)'

# 直接 main/master へのコミット検出
git log --oneline --first-parent main --no-merges --since='30 days ago' 2>/dev/null
```

### アクセス制御と職務分離

開発・テスト・本番環境でのアクセスを適切に分離する。

```bash
# 環境分離の確認
grep -rn --include='*.{ts,js,py,rb,go,java,json,yaml,yml}' \
  -iE '(NODE_ENV|RAILS_ENV|FLASK_ENV|APP_ENV|environment)' . | head -20

# 本番データベース接続文字列のハードコード
grep -rn --include='*.{ts,js,py,rb,go,java}' \
  -iE '(production|prod).*(host|url|connection|database)' . | \
  grep -v node_modules | grep -v '\.test\.' | grep -v '\.spec\.'

# 管理者権限のハードコード
grep -rn --include='*.{ts,js,py,rb,go,java}' \
  -iE '(isAdmin|is_admin|role.*admin|superuser|root.*access)' . | \
  grep -v node_modules
```

### 監査証跡とログの完全性

財務データの変更を追跡可能にする。

```bash
# 監査証跡の実装確認
grep -rn --include='*.{ts,js,py,rb,go,java}' \
  -iE '(audit.?trail|change.?log|revision|history|versioning|temporal)' .

# 財務データ関連のフィールド
grep -rn --include='*.{ts,js,py,rb,go,java}' \
  -iE '(amount|balance|transaction|ledger|invoice|revenue|expense|financial)' .

# 財務データの変更ログ
grep -rn --include='*.{ts,js,py,rb,go,java}' \
  -iE '(update|modify|delete|remove).*(amount|balance|transaction|ledger|invoice)' .
```

### 財務データの正確性と整合性

```bash
# 浮動小数点での金額計算（精度問題）
grep -rn --include='*.{ts,js,py,rb,go,java}' \
  -iE '(float|double|parseFloat).*(amount|price|balance|total)' .

# Decimal / BigNumber ライブラリの使用確認
grep -rn --include='*.{ts,js,py,rb,go,java}' \
  -iE '(Decimal|BigNumber|BigInt|bignumber|decimal\.js|dinero|currency)' .

# 丸め処理の確認
grep -rn --include='*.{ts,js,py,rb,go,java}' \
  -iE '(Math\.round|toFixed|ROUND_HALF|rounding)' . | \
  grep -iE '(amount|price|balance|total|currency)'
```

### SOX コード検出パターンまとめ

| 検出対象 | パターン | 深刻度 |
|----------|----------|--------|
| main への直接コミット | マージ以外の main コミット | High |
| コードレビュー未実施 | CODEOWNERS / PR ルール欠如 | High |
| 本番 DB 接続のハードコード | `production.*host` | Critical |
| 監査証跡の欠如 | audit 関連コードの不在 | High |
| 浮動小数点の金額計算 | `float.*amount` | Medium |
| 職務分離の未実装 | 環境分離なし | High |
| 財務データの変更ログ欠如 | update + 財務フィールドにログなし | High |

---

## 統合コンプライアンスチェックリスト

### PCI-DSS チェックリスト

- [ ] PAN がコード内にハードコードされていない
- [ ] PAN の保存時に AES-256 以上で暗号化されている
- [ ] PAN の表示時に先頭 6 桁 / 末尾 4 桁以外がマスクされている
- [ ] CVV / CVC はいかなる場合も保存されていない
- [ ] カード会員データの通信は TLS 1.2 以上で暗号化されている
- [ ] SSL 証明書の検証が無効化されていない
- [ ] 全依存パッケージの脆弱性が確認されている
- [ ] パスワードポリシーが 12 文字以上で実装されている
- [ ] MFA が管理者アカウントに実装されている
- [ ] カード会員データへの全アクセスが監査ログに記録されている
- [ ] 監査ログに PAN が平文で含まれていない
- [ ] テスト用カード番号が本番環境に残存していない

### HIPAA チェックリスト

- [ ] PHI フィールドが特定・分類されている
- [ ] PHI が保存時に暗号化されている
- [ ] PHI が通信時に暗号化されている（TLS 1.2 以上）
- [ ] PHI へのアクセスに RBAC が実装されている
- [ ] PHI アクセスの監査ログが記録されている
- [ ] ログ出力に PHI が含まれていない（サニタイゼーション済み）
- [ ] API レスポンスで Minimum Necessary が適用されている
- [ ] SELECT * が PHI テーブルで使用されていない
- [ ] サードパーティへの PHI 送信が BAA 対象に限定されている
- [ ] Analytics / Tracking に PHI が送信されていない
- [ ] セッションタイムアウトが適切に設定されている
- [ ] PHI を含むバックアップが暗号化されている

### SOX チェックリスト

- [ ] main ブランチへの直接コミットが制限されている
- [ ] PR レビューが必須に設定されている
- [ ] CODEOWNERS が適切に設定されている
- [ ] 開発・テスト・本番環境が分離されている
- [ ] 本番環境のクレデンシャルがコードにハードコードされていない
- [ ] 財務データの変更に監査証跡がある
- [ ] 金額計算に Decimal / BigNumber が使用されている（浮動小数点ではない）
- [ ] 管理者権限の付与が適切に制御されている
- [ ] デプロイメントの承認フローが存在する
- [ ] ログの改ざん防止措置が実装されている
