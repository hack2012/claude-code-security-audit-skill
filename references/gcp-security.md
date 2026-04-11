# GCP Security Testing Reference

GCP Security Best Practices に基づくセキュリティ検査ガイド。
gcloud CLI コマンドによる自動検査と CIS GCP Foundations Benchmark への準拠を確認する。

## IAM の検査

### サービスアカウント

```bash
# プロジェクト内のサービスアカウント一覧
gcloud iam service-accounts list --format='table(email, displayName, disabled)'

# ユーザー管理のサービスアカウントキー（CIS 1.4）
for sa in $(gcloud iam service-accounts list --format='value(email)'); do
  keys=$(gcloud iam service-accounts keys list --iam-account "$sa" \
    --managed-by user --format='value(name)')
  [ -n "$keys" ] && echo "USER MANAGED KEY: $sa"
done

# 90 日以上ローテーションされていないキー
for sa in $(gcloud iam service-accounts list --format='value(email)'); do
  gcloud iam service-accounts keys list --iam-account "$sa" \
    --managed-by user --format='table(name, validAfterTime, validBeforeTime)' 2>/dev/null
done

# デフォルトサービスアカウントの使用確認（CIS 1.5）
gcloud iam service-accounts list --format='value(email)' | grep -E 'compute@developer|appspot'
```

### IAM ポリシー・ロール

```bash
# プロジェクトレベルの IAM バインディング確認
gcloud projects get-iam-policy $(gcloud config get-value project) \
  --format='table(bindings.role, bindings.members)'

# 過度に広い権限（Editor/Owner ロール - CIS 1.6）
gcloud projects get-iam-policy $(gcloud config get-value project) \
  --flatten='bindings[].members' \
  --filter='bindings.role:(roles/editor OR roles/owner)' \
  --format='table(bindings.role, bindings.members)'

# allUsers / allAuthenticatedUsers バインディング（CIS 1.12）
gcloud projects get-iam-policy $(gcloud config get-value project) \
  --flatten='bindings[].members' \
  --filter='bindings.members:(allUsers OR allAuthenticatedUsers)' \
  --format='table(bindings.role, bindings.members)'

# カスタムロールの確認
gcloud iam roles list --project=$(gcloud config get-value project) \
  --format='table(name, title, stage)'

# Workload Identity の確認
gcloud iam service-accounts get-iam-policy <SERVICE_ACCOUNT_EMAIL> \
  --format='table(bindings.role, bindings.members)' 2>/dev/null
```

### 組織ポリシー

```bash
# 組織ポリシーの一覧
gcloud resource-manager org-policies list --project=$(gcloud config get-value project) \
  --format='table(constraint, listPolicy, booleanPolicy)' 2>/dev/null

# ドメイン制限ポリシーの確認（CIS 1.1）
gcloud resource-manager org-policies describe iam.allowedPolicyMemberDomains \
  --project=$(gcloud config get-value project) 2>/dev/null
```

## GCS の検査

### バケットアクセス

```bash
# 全バケット一覧
gsutil ls -p $(gcloud config get-value project)

# バケットの IAM ポリシー確認
for bucket in $(gsutil ls -p $(gcloud config get-value project)); do
  echo "=== $bucket ==="
  gsutil iam get "$bucket" 2>/dev/null | grep -E '(allUsers|allAuthenticatedUsers)'
done

# パブリックバケットの検出（CIS 5.1）
for bucket in $(gsutil ls -p $(gcloud config get-value project)); do
  gsutil iam get "$bucket" 2>/dev/null | grep -q 'allUsers' && echo "PUBLIC: $bucket"
done

# 均一バケットレベルアクセスの確認（CIS 5.2）
for bucket in $(gsutil ls -p $(gcloud config get-value project)); do
  gsutil uniformbucketlevelaccess get "$bucket" 2>/dev/null
done
```

### バケット暗号化・ロギング

```bash
# バケット暗号化設定（CMEK の確認）
for bucket in $(gsutil ls -p $(gcloud config get-value project)); do
  gsutil kms get "$bucket" 2>/dev/null || echo "DEFAULT ENCRYPTION: $bucket"
done

# バケットのアクセスログ
for bucket in $(gsutil ls -p $(gcloud config get-value project)); do
  gsutil logging get "$bucket" 2>/dev/null
done

# バケットのバージョニング
for bucket in $(gsutil ls -p $(gcloud config get-value project)); do
  gsutil versioning get "$bucket" 2>/dev/null
done

# バケットの保持ポリシー
for bucket in $(gsutil ls -p $(gcloud config get-value project)); do
  gsutil retention get "$bucket" 2>/dev/null
done
```

## VPC の検査

### ファイアウォールルール

```bash
# 全ファイアウォールルール一覧
gcloud compute firewall-rules list \
  --format='table(name, network, direction, priority, allowed, sourceRanges, targetTags)'

# 0.0.0.0/0 からの ingress 許可ルール（CIS 3.6/3.7）
gcloud compute firewall-rules list \
  --filter='sourceRanges=0.0.0.0/0 AND direction=INGRESS' \
  --format='table(name, allowed, targetTags, priority)'

# SSH（22）が全公開のルール（CIS 3.6）
gcloud compute firewall-rules list \
  --filter='sourceRanges=0.0.0.0/0 AND direction=INGRESS AND allowed[].ports=22' \
  --format='table(name, network, targetTags)'

# RDP（3389）が全公開のルール（CIS 3.7）
gcloud compute firewall-rules list \
  --filter='sourceRanges=0.0.0.0/0 AND direction=INGRESS AND allowed[].ports=3389' \
  --format='table(name, network, targetTags)'

# デフォルトネットワークの存在確認（CIS 3.1 - 削除推奨）
gcloud compute networks list --filter='name=default' --format='table(name, autoCreateSubnetworks)'
```

### VPC Service Controls・Private Access

```bash
# Private Google Access の確認（CIS 3.8）
gcloud compute networks subnets list \
  --format='table(name, region, privateIpGoogleAccess)'

# VPC Service Controls のペリメータ確認
gcloud access-context-manager perimeters list --format='table(name, title, status)' 2>/dev/null
```

## Compute の検査

```bash
# OS Login の有効化確認（CIS 4.4）
gcloud compute project-info describe \
  --format='value(commonInstanceMetadata.items[key=enable-oslogin].value)'

# シリアルポートの無効化確認（CIS 4.5）
gcloud compute instances list \
  --format='table(name, zone, metadata.items[key=serial-port-enable].value)'

# サービスアカウントスコープの確認（CIS 4.2）
gcloud compute instances list \
  --format='table(name, serviceAccounts[].email, serviceAccounts[].scopes)'

# デフォルトサービスアカウントを使用するインスタンス
gcloud compute instances list \
  --format='value(name, serviceAccounts[].email)' | grep 'compute@developer'

# Shielded VM の確認（CIS 4.8）
gcloud compute instances list \
  --format='table(name, shieldedInstanceConfig.enableSecureBoot, shieldedInstanceConfig.enableVtpm, shieldedInstanceConfig.enableIntegrityMonitoring)'

# パブリック IP を持つインスタンス
gcloud compute instances list \
  --format='table(name, zone, networkInterfaces[].accessConfigs[].natIP)' | grep -v 'None'

# ディスクの暗号化確認
gcloud compute disks list \
  --format='table(name, zone, diskEncryptionKey)'
```

## Cloud SQL の検査

```bash
# Cloud SQL インスタンス一覧
gcloud sql instances list --format='table(name, databaseVersion, settings.tier, settings.ipConfiguration.ipv4Enabled)'

# パブリック IP が有効な Cloud SQL（CIS 6.5）
gcloud sql instances list \
  --filter='settings.ipConfiguration.ipv4Enabled=true' \
  --format='table(name, databaseVersion)'

# SSL 未強制の Cloud SQL（CIS 6.4）
gcloud sql instances list --format='json' | \
  jq '.[] | select(.settings.ipConfiguration.requireSsl != true) | .name'

# 承認済みネットワークの確認（0.0.0.0/0 の検出）
for instance in $(gcloud sql instances list --format='value(name)'); do
  gcloud sql instances describe "$instance" \
    --format='value(settings.ipConfiguration.authorizedNetworks[].value)' | \
    grep '0\.0\.0\.0' && echo "OPEN NETWORK: $instance"
done

# 自動バックアップの確認（CIS 6.7）
gcloud sql instances list \
  --format='table(name, settings.backupConfiguration.enabled, settings.backupConfiguration.pointInTimeRecoveryEnabled)'
```

## Cloud Functions の検査

```bash
# Cloud Functions 一覧
gcloud functions list --format='table(name, runtime, serviceAccountEmail, ingressSettings)'

# 全公開の Cloud Functions（ingress が all-traffic）
gcloud functions list \
  --filter='ingressSettings=ALLOW_ALL' \
  --format='table(name, ingressSettings)'

# サービスアカウントの確認
gcloud functions list \
  --format='table(name, serviceAccountEmail)' | grep 'appspot.gserviceaccount.com'

# VPC コネクタ未設定の関数
gcloud functions list \
  --format='table(name, vpcConnector)' | grep -E '\s*$'

# 環境変数内のシークレット
for fn in $(gcloud functions list --format='value(name)'); do
  gcloud functions describe "$fn" --format='json' | \
    jq '.environmentVariables // {} | to_entries[] | select(.key | test("SECRET|PASSWORD|TOKEN|KEY|CREDENTIAL"; "i"))' 2>/dev/null && echo "  -> $fn"
done
```

## KMS の検査

```bash
# KMS キーリング一覧
gcloud kms keyrings list --location=global --format='table(name)'

# キーローテーション期間の確認（CIS 1.10）
for keyring in $(gcloud kms keyrings list --location=global --format='value(name)'); do
  for key in $(gcloud kms keys list --keyring="$keyring" --location=global --format='value(name)'); do
    gcloud kms keys describe "$key" --keyring="$keyring" --location=global \
      --format='table(name, rotationPeriod, nextRotationTime)' 2>/dev/null
  done
done

# KMS キーの IAM ポリシー確認
for keyring in $(gcloud kms keyrings list --location=global --format='value(name)'); do
  for key in $(gcloud kms keys list --keyring="$keyring" --location=global --format='value(name)'); do
    gcloud kms keys get-iam-policy "$key" --keyring="$keyring" --location=global \
      --format='table(bindings.role, bindings.members)' 2>/dev/null
  done
done
```

## Cloud Audit Logs の検査

```bash
# 監査ログの設定確認（CIS 2.1）
gcloud projects get-iam-policy $(gcloud config get-value project) \
  --format='json' | jq '.auditConfigs'

# データアクセスログの有効化確認
gcloud projects get-iam-policy $(gcloud config get-value project) \
  --format='json' | jq '.auditConfigs[] | select(.auditLogConfigs[].logType == "DATA_READ" or .auditLogConfigs[].logType == "DATA_WRITE")'

# ログシンクの確認（エクスポート先）
gcloud logging sinks list --format='table(name, destination, filter)'

# ログベースのメトリクスとアラート
gcloud logging metrics list --format='table(name, filter)'
```

## Security Command Center の検査

```bash
# Security Command Center の検出結果
gcloud scc findings list $(gcloud config get-value project) \
  --filter='state="ACTIVE" AND severity="HIGH" OR severity="CRITICAL"' \
  --format='table(finding.category, finding.severity, finding.resourceName)' 2>/dev/null

# コンプライアンス状態の確認
gcloud scc sources list --organization=$(gcloud organizations list --format='value(name)' | head -1) 2>/dev/null
```

## Cloud Armor の検査

```bash
# セキュリティポリシー一覧
gcloud compute security-policies list --format='table(name, type)'

# ポリシールールの確認
for policy in $(gcloud compute security-policies list --format='value(name)'); do
  echo "=== $policy ==="
  gcloud compute security-policies rules list "$policy" \
    --format='table(priority, action, match.config.srcIpRanges, description)'
done

# WAF ルールの確認
for policy in $(gcloud compute security-policies list --format='value(name)'); do
  gcloud compute security-policies describe "$policy" \
    --format='json' | jq '.rules[] | select(.match.expr != null) | {priority, action, expression: .match.expr.expression}'
done

# DDoS 保護（Adaptive Protection）
gcloud compute security-policies list --format='json' | \
  jq '.[] | {name, adaptiveProtectionConfig}'
```

## Secret Manager の検査

```bash
# シークレット一覧
gcloud secrets list --format='table(name, replication.automatic, createTime)'

# シークレットの IAM バインディング確認
for secret in $(gcloud secrets list --format='value(name)'); do
  echo "=== $secret ==="
  gcloud secrets get-iam-policy "$secret" \
    --format='table(bindings.role, bindings.members)' 2>/dev/null
done

# ローテーション設定の確認
for secret in $(gcloud secrets list --format='value(name)'); do
  gcloud secrets describe "$secret" \
    --format='json' | jq '{name: .name, rotation: .rotation}' 2>/dev/null
done
```

## コードベースの静的解析

```bash
# GCP サービスアカウントキーファイルの検出
grep -rn --include='*.{ts,tsx,js,jsx,py,go,java}' \
  -E '(private_key_id|client_email.*gserviceaccount)' . | grep -v node_modules

# GCP API キーのハードコード
grep -rn --include='*.{ts,tsx,js,jsx,py,go,java}' \
  -E 'AIza[0-9A-Za-z_-]{35}' . | grep -v node_modules

# サービスアカウント JSON キーファイル
find . -name '*.json' -exec grep -l 'private_key_id' {} \; 2>/dev/null | grep -v node_modules
```

## よくある設定ミス

| 深刻度 | 設定ミス | CIS | 影響 |
|--------|----------|-----|------|
| Critical | allUsers へのパブリック IAM バインディング | 1.12 | 全ユーザーにリソースアクセス |
| Critical | GCS バケットのパブリック公開 | 5.1 | データの全公開 |
| Critical | Cloud SQL の 0.0.0.0/0 承認ネットワーク | 6.5 | データベースへの直接アクセス |
| Critical | サービスアカウントキーのソースコード含有 | 1.4 | 認証情報の漏洩 |
| High | Editor/Owner ロールの過剰付与 | 1.6 | 過度な権限 |
| High | ファイアウォールで SSH が全公開 | 3.6 | 不正アクセスリスク |
| High | Cloud SQL の SSL 未強制 | 6.4 | 通信の盗聴 |
| High | デフォルトネットワークの残存 | 3.1 | 意図しないネットワーク公開 |
| Medium | OS Login 未有効化 | 4.4 | SSH 鍵管理の分散 |
| Medium | KMS キーローテーション未設定 | 1.10 | 長期間同一鍵の使用 |
| Medium | Cloud Audit Logs のデータアクセスログ未設定 | 2.1 | 監査証跡の不足 |
| Medium | Shielded VM 未有効化 | 4.8 | ブート整合性の未検証 |
| Low | 均一バケットレベルアクセス未使用 | 5.2 | ACL 管理の複雑化 |
| Low | Private Google Access 未設定 | 3.8 | パブリック IP 経由の通信 |

## セキュリティチェックリスト

### IAM（CIS 1.x）
- [ ] allUsers / allAuthenticatedUsers のバインディングがない
- [ ] Editor/Owner ロールが最小限のメンバーに制限されている
- [ ] サービスアカウントキーが定期的にローテーションされている
- [ ] デフォルトサービスアカウントが使用されていない
- [ ] Workload Identity が可能な箇所で使用されている
- [ ] 組織ポリシーでドメイン制限が設定されている

### GCS（CIS 5.x）
- [ ] パブリックバケットが存在しない
- [ ] 均一バケットレベルアクセスが有効
- [ ] CMEK またはデフォルト暗号化が設定されている
- [ ] バケットのアクセスログが有効
- [ ] バージョニングが有効

### ネットワーク（CIS 3.x）
- [ ] デフォルトネットワークが削除されている
- [ ] SSH（22）が特定 IP に制限されている
- [ ] RDP（3389）が特定 IP に制限されている
- [ ] Private Google Access が有効
- [ ] VPC Service Controls が設定されている

### コンピュート（CIS 4.x）
- [ ] OS Login が有効
- [ ] Shielded VM が有効
- [ ] デフォルトサービスアカウントを使用するインスタンスがない
- [ ] シリアルポートが無効化されている
- [ ] パブリック IP が最小限

### データベース（CIS 6.x）
- [ ] Cloud SQL にパブリック IP が設定されていない
- [ ] SSL が強制されている
- [ ] 承認済みネットワークに 0.0.0.0/0 がない
- [ ] 自動バックアップが有効
- [ ] Point-in-Time Recovery が有効

### ロギング・モニタリング（CIS 2.x）
- [ ] Cloud Audit Logs のデータアクセスログが有効
- [ ] ログシンクが適切に設定されている
- [ ] ログベースのアラートが設定されている
- [ ] Security Command Center が有効

### シークレット管理
- [ ] Secret Manager を使用している
- [ ] シークレットのローテーションが設定されている
- [ ] サービスアカウントキーがソースコードに含まれていない
- [ ] API キーがハードコードされていない
