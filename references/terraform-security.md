# Terraform Security Testing Reference

Terraform の Infrastructure as Code 設定レベルのセキュリティ検査ガイド。
AWS/GCP/Azure の主要リソースにおけるミスコンフィギュレーションを静的解析で検出する。

## State ファイルのセキュリティ

### Remote State の暗号化確認

```bash
# backend 設定で暗号化が有効か確認
grep -rn --include='*.tf' -E 'backend\s+"s3"' . | head -20
grep -rn --include='*.tf' -A 10 'backend\s+"s3"' . | grep -i 'encrypt'

# State ファイルがローカルに残存していないか
find . -name 'terraform.tfstate' -o -name 'terraform.tfstate.backup' 2>/dev/null

# .gitignore に state ファイルが含まれているか
grep -n 'tfstate' .gitignore 2>/dev/null
```

### State ファイル内のシークレット検出

```bash
# State ファイル内のパスワード・トークン
grep -iE '(password|secret|token|api_key|private_key)' terraform.tfstate 2>/dev/null | head -20

# tfvars ファイル内のハードコードされた機密情報
grep -rn --include='*.tfvars' -iE '(password|secret|token|api_key|private_key)\s*=' .
```

## Provider 設定の検査

```bash
# ハードコードされた認証情報の検出
grep -rn --include='*.tf' -E '(access_key|secret_key|api_key|token)\s*=' .

# assume_role の使用確認（推奨）
grep -rn --include='*.tf' -A 5 'assume_role' .

# Provider のバージョン固定確認
grep -rn --include='*.tf' -E 'required_providers' -A 20 . | grep -E '(version|source)'
```

## AWS リソースの検査

### S3 バケットポリシー

```bash
# パブリックアクセスブロック設定の確認
grep -rn --include='*.tf' -B 2 -A 10 'aws_s3_bucket_public_access_block' .

# バケット暗号化設定
grep -rn --include='*.tf' -B 2 -A 10 'aws_s3_bucket_server_side_encryption' .

# バケットバージョニング
grep -rn --include='*.tf' -B 2 -A 5 'aws_s3_bucket_versioning' .

# バケットロギング
grep -rn --include='*.tf' -B 2 -A 5 'aws_s3_bucket_logging' .

# パブリック ACL の検出
grep -rn --include='*.tf' -E 'acl\s*=\s*"public' .
```

### IAM ロール・ポリシー

```bash
# ワイルドカードアクション（"*"）の検出
grep -rn --include='*.tf' -E '"Action"\s*:\s*"\*"' .
grep -rn --include='*.tf' -E 'actions\s*=\s*\["\*"\]' .

# ワイルドカードリソースの検出
grep -rn --include='*.tf' -E '"Resource"\s*:\s*"\*"' .
grep -rn --include='*.tf' -E 'resources\s*=\s*\["\*"\]' .

# AssumeRole の信頼ポリシー（過度に広いプリンシパル）
grep -rn --include='*.tf' -E '"Principal"\s*:\s*"\*"' .
```

### Security Groups

```bash
# 全ポート開放（0.0.0.0/0）の検出
grep -rn --include='*.tf' -B 5 -A 5 '0\.0\.0\.0/0' . | grep -E '(ingress|cidr_blocks)'

# SSH ポート（22）の全公開
grep -rn --include='*.tf' -B 10 'from_port\s*=\s*22' . | grep -E '(0\.0\.0\.0/0|cidr_blocks)'

# RDP ポート（3389）の全公開
grep -rn --include='*.tf' -B 10 'from_port\s*=\s*3389' . | grep -E '(0\.0\.0\.0/0|cidr_blocks)'

# egress 全許可の確認
grep -rn --include='*.tf' -B 3 -A 10 'egress' . | grep '0\.0\.0\.0/0'
```

### KMS・暗号化

```bash
# KMS キーローテーションの確認
grep -rn --include='*.tf' -B 5 -A 10 'aws_kms_key' . | grep 'enable_key_rotation'

# EBS 暗号化のデフォルト設定
grep -rn --include='*.tf' 'aws_ebs_encryption_by_default' .

# RDS 暗号化
grep -rn --include='*.tf' -B 5 -A 15 'aws_db_instance' . | grep 'storage_encrypted'
```

### RDS

```bash
# パブリックアクセス可能な RDS インスタンス
grep -rn --include='*.tf' -B 5 -A 15 'aws_db_instance' . | grep 'publicly_accessible'

# 自動バックアップの確認
grep -rn --include='*.tf' -B 5 -A 15 'aws_db_instance' . | grep 'backup_retention_period'

# 削除保護
grep -rn --include='*.tf' -B 5 -A 15 'aws_db_instance' . | grep 'deletion_protection'

# マスターパスワードのハードコード
grep -rn --include='*.tf' -E 'password\s*=\s*"[^"$]' .
```

### Lambda

```bash
# 過剰な IAM ロール（"*" アクション）の検出
grep -rn --include='*.tf' -B 5 -A 20 'aws_iam_role_policy.*lambda' .

# 環境変数内のシークレット
grep -rn --include='*.tf' -B 5 -A 20 'aws_lambda_function' . | grep -iE '(password|secret|token|key)'

# VPC 設定の確認
grep -rn --include='*.tf' -B 5 -A 20 'aws_lambda_function' . | grep 'vpc_config'
```

## GCP リソースの検査

```bash
# パブリック IAM バインディング（allUsers / allAuthenticatedUsers）
grep -rn --include='*.tf' -E '(allUsers|allAuthenticatedUsers)' .

# GCS バケットの公開設定
grep -rn --include='*.tf' -B 5 -A 10 'google_storage_bucket_iam' . | grep -E '(allUsers|allAuthenticatedUsers)'

# Compute ファイアウォールの全公開
grep -rn --include='*.tf' -B 5 -A 10 'google_compute_firewall' . | grep '0\.0\.0\.0/0'

# Cloud SQL のパブリック IP
grep -rn --include='*.tf' -B 5 -A 15 'google_sql_database_instance' . | grep -E '(ipv4_enabled|authorized_networks)'
```

## Azure リソースの検査

```bash
# NSG で全ポート許可ルール
grep -rn --include='*.tf' -B 5 -A 10 'azurerm_network_security_rule' . | grep -E '(0\.0\.0\.0|\*)'

# Key Vault のソフトデリート無効
grep -rn --include='*.tf' -B 5 -A 15 'azurerm_key_vault' . | grep 'soft_delete'

# Storage Account の HTTPS 強制
grep -rn --include='*.tf' -B 5 -A 15 'azurerm_storage_account' . | grep 'enable_https_traffic_only'

# RBAC 設定
grep -rn --include='*.tf' -B 5 -A 10 'azurerm_role_assignment' .
```

## ネットワーク設定の検査

```bash
# 0.0.0.0/0 への過度なアクセス許可（全プロバイダー共通）
grep -rn --include='*.tf' '0\.0\.0\.0/0' .

# ::/0（IPv6 全許可）
grep -rn --include='*.tf' '::/0' .

# VPC/VNet 設定のサブネット確認
grep -rn --include='*.tf' -B 5 -A 10 'cidr_block' .
```

## ロギング・監査設定の検査

```bash
# CloudTrail の設定
grep -rn --include='*.tf' -B 5 -A 15 'aws_cloudtrail' . | grep -E '(is_multi_region|enable_log_file_validation)'

# VPC Flow Logs
grep -rn --include='*.tf' -B 5 -A 10 'aws_flow_log' .

# GCP Audit Logs
grep -rn --include='*.tf' -B 5 -A 10 'google_project_iam_audit_config' .

# Azure Diagnostic Settings
grep -rn --include='*.tf' -B 5 -A 10 'azurerm_monitor_diagnostic_setting' .
```

## モジュールのセキュリティ

```bash
# 外部モジュールソースの確認（未ピン止めバージョン）
grep -rn --include='*.tf' -E 'source\s*=\s*"(github|git::http|bitbucket|generic)' .

# レジストリモジュールのバージョン固定確認
grep -rn --include='*.tf' -B 2 -A 5 'module\s+"' . | grep -E '(source|version)'

# ref なしの Git ソース
grep -rn --include='*.tf' -E 'source\s*=\s*"git::' . | grep -v 'ref='
```

## シークレットの検出

```bash
# .tf ファイル内のハードコードされた機密情報
grep -rn --include='*.tf' --include='*.tfvars' \
  -iE '(password|secret|token|api_key|private_key|credentials)\s*=\s*"[^"$\{]' .

# AWS アクセスキーパターン
grep -rn --include='*.tf' --include='*.tfvars' \
  -E '(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}' .

# base64 エンコードされた認証情報
grep -rn --include='*.tf' -E '[A-Za-z0-9+/]{40,}={0,2}' . | grep -iE '(key|secret|password|token)'

# .tfvars が .gitignore に含まれているか
grep -n 'tfvars' .gitignore 2>/dev/null
```

## tfsec / checkov 統合

```bash
# tfsec の実行
tfsec . --format json 2>/dev/null | jq '.results[] | {rule_id, severity, description, location}'

# tfsec の Critical/High のみ
tfsec . --minimum-severity HIGH 2>/dev/null

# checkov の実行
checkov -d . --framework terraform --output json 2>/dev/null | jq '.results.failed_checks[] | {check_id, check_type, name, guideline}'

# checkov の CIS ベンチマーク
checkov -d . --check-type terraform --framework terraform --compact 2>/dev/null
```

## よくある設定ミス

| 深刻度 | 設定ミス | 影響 |
|--------|----------|------|
| Critical | State ファイルに平文シークレット | 認証情報の漏洩 |
| Critical | S3 バケットのパブリック ACL | データの全公開 |
| Critical | IAM ポリシーで `Action: "*"` | 全 AWS サービスへのフルアクセス |
| Critical | Security Group で 0.0.0.0/0 の全ポート許可 | 全ポートが外部公開 |
| High | .tf ファイル内のハードコードパスワード | Git 履歴に認証情報が残存 |
| High | KMS キーローテーション未設定 | 長期間同一鍵の使用 |
| High | RDS のパブリックアクセス有効 | データベースへの直接アクセス |
| High | CloudTrail の複数リージョン無効 | 監査ログの欠損 |
| Medium | モジュールのバージョン未固定 | サプライチェーン攻撃リスク |
| Medium | EBS 暗号化未設定 | 物理メディアからのデータ漏洩 |
| Medium | VPC Flow Logs 未設定 | ネットワーク通信の監視不可 |
| Medium | Provider バージョン未固定 | 予期しない変更の導入 |
| Low | State ファイルの .gitignore 漏れ | State の誤コミット |
| Low | tfvars の .gitignore 漏れ | 変数ファイルの誤コミット |

## セキュリティチェックリスト

### State 管理
- [ ] Remote backend（S3/GCS/Azure Blob）を使用している
- [ ] State ファイルの暗号化が有効
- [ ] State ファイルへのアクセスが IAM で制限されている
- [ ] ローカルに State ファイルが残存していない
- [ ] .gitignore に `*.tfstate*` が含まれている

### 認証情報
- [ ] .tf ファイルにハードコードされた認証情報がない
- [ ] 環境変数または Vault 経由で認証情報を管理している
- [ ] Provider で assume_role を使用している
- [ ] .tfvars が .gitignore に含まれている
- [ ] AWS アクセスキーがソースコードに含まれていない

### ネットワーク
- [ ] 0.0.0.0/0 の ingress ルールが最小限
- [ ] SSH（22）/RDP（3389）が特定 IP に制限されている
- [ ] VPC/VNet のサブネット設計が適切
- [ ] VPC Flow Logs が有効

### 暗号化
- [ ] S3 バケットの暗号化が有効
- [ ] EBS ボリュームの暗号化が有効
- [ ] RDS の暗号化が有効
- [ ] KMS キーローテーションが有効

### ロギング・監査
- [ ] CloudTrail がマルチリージョンで有効
- [ ] ログファイルの検証が有効
- [ ] VPC Flow Logs が設定されている
- [ ] 監査ログが適切に保存されている

### モジュール
- [ ] 外部モジュールのバージョンが固定されている
- [ ] モジュールソースが信頼できるレジストリ/リポジトリ
- [ ] Git ソースに ref（コミットハッシュ）が指定されている

### IaC スキャン
- [ ] tfsec または checkov が CI/CD に統合されている
- [ ] Critical/High の検出が 0 件
- [ ] CIS ベンチマークに準拠している
