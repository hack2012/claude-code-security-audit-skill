# AWS Security Testing Reference

AWS Well-Architected Framework Security Pillar に基づくセキュリティ検査ガイド。
AWS CLI コマンドによる自動検査と CIS AWS Foundations Benchmark への準拠を確認する。

## IAM の検査

### ルートアカウント・MFA

```bash
# ルートアカウントの MFA 状態確認（CIS 1.5）
aws iam get-account-summary --query 'SummaryMap.AccountMFAEnabled'

# ルートアカウントのアクセスキー確認（CIS 1.4 - 無効であること）
aws iam get-account-summary --query 'SummaryMap.AccountAccessKeysPresent'

# MFA が未設定のユーザー一覧（CIS 1.10）
aws iam generate-credential-report > /dev/null 2>&1
aws iam get-credential-report --output text --query 'Content' | base64 -d | \
  awk -F, '$4 == "true" && $8 == "false" {print $1}'
```

### アクセスキーの管理

```bash
# 90 日以上ローテーションされていないアクセスキー（CIS 1.14）
aws iam generate-credential-report > /dev/null 2>&1
aws iam get-credential-report --output text --query 'Content' | base64 -d | \
  awk -F, 'NR>1 && $9 == "true" {print $1, $10}'

# 未使用のアクセスキー（90 日以上使用なし - CIS 1.12）
aws iam generate-credential-report > /dev/null 2>&1
aws iam get-credential-report --output text --query 'Content' | base64 -d | \
  awk -F, 'NR>1 && $9 == "true" && $11 != "N/A" {print $1, $11}'

# 複数のアクティブアクセスキーを持つユーザー
for user in $(aws iam list-users --query 'Users[].UserName' --output text); do
  count=$(aws iam list-access-keys --user-name "$user" --query 'length(AccessKeyMetadata[?Status==`Active`])' --output text)
  [ "$count" -gt 1 ] && echo "WARNING: $user has $count active keys"
done
```

### IAM ポリシー

```bash
# 管理者権限（AdministratorAccess）が付与されたユーザー/ロール
aws iam list-entities-for-policy \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess \
  --query '{Users: PolicyUsers, Roles: PolicyRoles, Groups: PolicyGroups}'

# ワイルドカードアクション（"*"）を含むカスタムポリシー
for arn in $(aws iam list-policies --scope Local --query 'Policies[].Arn' --output text); do
  version=$(aws iam get-policy --policy-arn "$arn" --query 'Policy.DefaultVersionId' --output text)
  aws iam get-policy-version --policy-arn "$arn" --version-id "$version" --query 'PolicyVersion.Document' --output json | \
    grep -l '"Action": "\*"' 2>/dev/null && echo "WILDCARD: $arn"
done

# インラインポリシーを持つユーザー（グループポリシーを推奨）
for user in $(aws iam list-users --query 'Users[].UserName' --output text); do
  policies=$(aws iam list-user-policies --user-name "$user" --query 'PolicyNames' --output text)
  [ -n "$policies" ] && echo "INLINE POLICY: $user - $policies"
done

# パスワードポリシーの確認（CIS 1.8-1.11）
aws iam get-account-password-policy 2>/dev/null
```

## S3 の検査

### パブリックアクセス

```bash
# アカウントレベルのパブリックアクセスブロック（CIS 2.1.5）
aws s3control get-public-access-block --account-id $(aws sts get-caller-identity --query Account --output text) 2>/dev/null

# 全バケットのパブリックアクセスブロック確認
for bucket in $(aws s3api list-buckets --query 'Buckets[].Name' --output text); do
  echo "=== $bucket ==="
  aws s3api get-public-access-block --bucket "$bucket" 2>/dev/null || echo "NOT CONFIGURED"
done

# パブリック ACL を持つバケット
for bucket in $(aws s3api list-buckets --query 'Buckets[].Name' --output text); do
  acl=$(aws s3api get-bucket-acl --bucket "$bucket" --query 'Grants[?Grantee.URI==`http://acs.amazonaws.com/groups/global/AllUsers` || Grantee.URI==`http://acs.amazonaws.com/groups/global/AuthenticatedUsers`]' --output text)
  [ -n "$acl" ] && echo "PUBLIC: $bucket"
done
```

### S3 暗号化・ロギング

```bash
# バケット暗号化の確認（CIS 2.1.1）
for bucket in $(aws s3api list-buckets --query 'Buckets[].Name' --output text); do
  aws s3api get-bucket-encryption --bucket "$bucket" 2>/dev/null || echo "NO ENCRYPTION: $bucket"
done

# バージョニングの確認
for bucket in $(aws s3api list-buckets --query 'Buckets[].Name' --output text); do
  status=$(aws s3api get-bucket-versioning --bucket "$bucket" --query 'Status' --output text)
  [ "$status" != "Enabled" ] && echo "VERSIONING OFF: $bucket"
done

# アクセスログの確認（CIS 2.1.3）
for bucket in $(aws s3api list-buckets --query 'Buckets[].Name' --output text); do
  aws s3api get-bucket-logging --bucket "$bucket" --query 'LoggingEnabled' 2>/dev/null || echo "NO LOGGING: $bucket"
done

# SSL 強制ポリシーの確認
for bucket in $(aws s3api list-buckets --query 'Buckets[].Name' --output text); do
  aws s3api get-bucket-policy --bucket "$bucket" --output text 2>/dev/null | \
    grep -q 'aws:SecureTransport.*false' || echo "NO SSL ENFORCEMENT: $bucket"
done
```

## VPC の検査

### Security Groups

```bash
# 全ポート開放の Security Group（CIS 5.1-5.4）
aws ec2 describe-security-groups \
  --filters Name=ip-permission.cidr,Values=0.0.0.0/0 \
  --query 'SecurityGroups[].{ID:GroupId, Name:GroupName, Rules:IpPermissions[?contains(IpRanges[].CidrIp, `0.0.0.0/0`)]}'

# SSH（22）が全公開の Security Group
aws ec2 describe-security-groups \
  --filters Name=ip-permission.from-port,Values=22 Name=ip-permission.cidr,Values=0.0.0.0/0 \
  --query 'SecurityGroups[].{ID:GroupId, Name:GroupName}'

# RDP（3389）が全公開の Security Group
aws ec2 describe-security-groups \
  --filters Name=ip-permission.from-port,Values=3389 Name=ip-permission.cidr,Values=0.0.0.0/0 \
  --query 'SecurityGroups[].{ID:GroupId, Name:GroupName}'

# デフォルト Security Group にルールが残存（CIS 5.4）
for vpc in $(aws ec2 describe-vpcs --query 'Vpcs[].VpcId' --output text); do
  aws ec2 describe-security-groups --filters Name=vpc-id,Values=$vpc Name=group-name,Values=default \
    --query 'SecurityGroups[?length(IpPermissions) > `0` || length(IpPermissionsEgress) > `0`].{VPC: VpcId, SG: GroupId}'
done
```

### VPC Flow Logs・NACL

```bash
# VPC Flow Logs の有効化確認（CIS 3.9）
for vpc in $(aws ec2 describe-vpcs --query 'Vpcs[].VpcId' --output text); do
  logs=$(aws ec2 describe-flow-logs --filter Name=resource-id,Values=$vpc --query 'FlowLogs[].FlowLogId' --output text)
  [ -z "$logs" ] && echo "NO FLOW LOGS: $vpc"
done

# VPC エンドポイントの確認
aws ec2 describe-vpc-endpoints --query 'VpcEndpoints[].{VPC:VpcId, Service:ServiceName, Type:VpcEndpointType}'
```

## EC2 の検査

```bash
# IMDSv2 強制の確認（CIS 5.6）
aws ec2 describe-instances \
  --query 'Reservations[].Instances[].{ID:InstanceId, IMDS:MetadataOptions.HttpTokens}' | \
  grep -B1 'optional'

# EBS 暗号化のデフォルト設定
aws ec2 get-ebs-encryption-by-default --query 'EbsEncryptionByDefault'

# 暗号化されていない EBS ボリューム
aws ec2 describe-volumes \
  --filters Name=encrypted,Values=false \
  --query 'Volumes[].{ID:VolumeId, State:State, Size:Size}'

# パブリック AMI の確認
aws ec2 describe-images --owners self \
  --query 'Images[?Public==`true`].{ID:ImageId, Name:Name}'
```

## RDS の検査

```bash
# パブリックアクセス可能な RDS インスタンス
aws rds describe-db-instances \
  --query 'DBInstances[?PubliclyAccessible==`true`].{ID:DBInstanceIdentifier, Engine:Engine}'

# 暗号化されていない RDS インスタンス（CIS 2.3.1）
aws rds describe-db-instances \
  --query 'DBInstances[?StorageEncrypted==`false`].{ID:DBInstanceIdentifier, Engine:Engine}'

# 自動バックアップの確認
aws rds describe-db-instances \
  --query 'DBInstances[?BackupRetentionPeriod==`0`].{ID:DBInstanceIdentifier, Engine:Engine}'

# 削除保護の確認
aws rds describe-db-instances \
  --query 'DBInstances[?DeletionProtection==`false`].{ID:DBInstanceIdentifier, Engine:Engine}'

# SSL 強制の確認
for id in $(aws rds describe-db-instances --query 'DBInstances[].DBInstanceIdentifier' --output text); do
  pg=$(aws rds describe-db-instances --db-instance-identifier "$id" --query 'DBInstances[0].DBParameterGroups[0].DBParameterGroupName' --output text)
  aws rds describe-db-parameters --db-parameter-group-name "$pg" --query 'Parameters[?ParameterName==`rds.force_ssl`].{Name:ParameterName, Value:ParameterValue}'
done
```

## Lambda の検査

```bash
# Lambda 関数の実行ロール確認
aws lambda list-functions \
  --query 'Functions[].{Name:FunctionName, Role:Role, Runtime:Runtime}'

# 環境変数内のシークレット検出
for fn in $(aws lambda list-functions --query 'Functions[].FunctionName' --output text); do
  aws lambda get-function-configuration --function-name "$fn" \
    --query 'Environment.Variables' 2>/dev/null | \
    grep -iE '(password|secret|token|key|credential)' && echo "  -> $fn"
done

# VPC 未設定の Lambda 関数
aws lambda list-functions \
  --query 'Functions[?VpcConfig.VpcId==`null` || VpcConfig.VpcId==``].FunctionName'
```

## KMS の検査

```bash
# キーローテーションの確認（CIS 3.8）
for key in $(aws kms list-keys --query 'Keys[].KeyId' --output text); do
  rotation=$(aws kms get-key-rotation-status --key-id "$key" --query 'KeyRotationEnabled' --output text 2>/dev/null)
  [ "$rotation" = "false" ] && echo "NO ROTATION: $key"
done

# キーポリシーの確認（過度に広いアクセス）
for key in $(aws kms list-keys --query 'Keys[].KeyId' --output text); do
  aws kms get-key-policy --key-id "$key" --policy-name default --output text 2>/dev/null | \
    grep -q '"Principal": "\*"' && echo "WILDCARD PRINCIPAL: $key"
done
```

## CloudTrail の検査

```bash
# CloudTrail の設定確認（CIS 3.1-3.4）
aws cloudtrail describe-trails --query 'trailList[].{Name:Name, IsMultiRegion:IsMultiRegionTrail, LogValidation:LogFileValidationEnabled, S3Bucket:S3BucketName, KmsKey:KmsKeyId}'

# CloudTrail が有効か
aws cloudtrail get-trail-status --name $(aws cloudtrail describe-trails --query 'trailList[0].Name' --output text) \
  --query '{IsLogging:IsLogging, LatestDeliveryTime:LatestDeliveryTime}'

# CloudTrail ログの S3 バケットがパブリックでないか確認
trail_bucket=$(aws cloudtrail describe-trails --query 'trailList[0].S3BucketName' --output text)
aws s3api get-bucket-acl --bucket "$trail_bucket" --query 'Grants[?Grantee.URI!=`null`]'
```

## GuardDuty の検査

```bash
# GuardDuty が有効か（CIS 4.15）
aws guardduty list-detectors --query 'DetectorIds'

# GuardDuty の検出結果（High 以上）
detector_id=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text)
aws guardduty list-findings --detector-id "$detector_id" \
  --finding-criteria '{"Criterion":{"severity":{"Gte":7}}}' 2>/dev/null
```

## Secrets Manager の検査

```bash
# ローテーション未設定のシークレット
aws secretsmanager list-secrets \
  --query 'SecretList[?RotationEnabled==`false`].{Name:Name, LastChanged:LastChangedDate}'

# ローテーションスケジュールの確認
aws secretsmanager list-secrets \
  --query 'SecretList[].{Name:Name, RotationEnabled:RotationEnabled, RotationDays:RotationRules.AutomaticallyAfterDays}'
```

## WAF の検査

```bash
# WAF WebACL の一覧
aws wafv2 list-web-acls --scope REGIONAL --query 'WebACLs[].{Name:Name, ID:Id}'

# マネージドルールグループの確認
for acl_id in $(aws wafv2 list-web-acls --scope REGIONAL --query 'WebACLs[].Id' --output text); do
  acl_name=$(aws wafv2 list-web-acls --scope REGIONAL --query "WebACLs[?Id=='$acl_id'].Name" --output text)
  aws wafv2 get-web-acl --scope REGIONAL --name "$acl_name" --id "$acl_id" \
    --query 'WebACL.Rules[].{Name:Name, Priority:Priority}' 2>/dev/null
done

# レート制限ルールの確認
aws wafv2 list-web-acls --scope REGIONAL --query 'WebACLs[].Name' --output text
```

## ECS/EKS の検査

```bash
# ECS タスク定義の特権モード確認
for td in $(aws ecs list-task-definitions --query 'taskDefinitionArns' --output text); do
  aws ecs describe-task-definition --task-definition "$td" \
    --query 'taskDefinition.containerDefinitions[?privileged==`true`].name' --output text | \
    grep -v '^$' && echo "PRIVILEGED: $td"
done

# EKS クラスタの RBAC 確認
for cluster in $(aws eks list-clusters --query 'clusters' --output text); do
  aws eks describe-cluster --name "$cluster" \
    --query 'cluster.{Name:name, Endpoint:endpoint, PublicAccess:resourcesVpcConfig.endpointPublicAccess}'
done
```

## コードベースの静的解析

```bash
# AWS アクセスキーのハードコード
grep -rn --include='*.{ts,tsx,js,jsx,py,go,java,rb}' \
  -E '(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}' . | grep -v node_modules

# AWS シークレットキーのパターン
grep -rn --include='*.{ts,tsx,js,jsx,py,go,java,rb}' \
  -E '[A-Za-z0-9/+=]{40}' . | grep -iE '(aws_secret|secret_access)' | grep -v node_modules

# .env ファイル内の AWS 認証情報
grep -rn -E '(AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN)' .env* 2>/dev/null
```

## よくある設定ミス

| 深刻度 | 設定ミス | CIS | 影響 |
|--------|----------|-----|------|
| Critical | ルートアカウントにアクセスキー | 1.4 | 全リソースへのフルアクセス |
| Critical | S3 バケットがパブリック公開 | 2.1.5 | データの全公開 |
| Critical | IAM ポリシーで `*` アクション | - | 過剰な権限 |
| Critical | Security Group で全ポート公開 | 5.1 | 全サービスが外部露出 |
| High | ルートアカウントの MFA 未設定 | 1.5 | アカウント乗っ取りリスク |
| High | CloudTrail 未有効化 | 3.1 | 監査証跡の欠如 |
| High | RDS がパブリックアクセス可能 | - | データベースへの直接アクセス |
| High | IMDSv2 未強制 | 5.6 | SSRF 経由の認証情報窃取 |
| High | KMS キーローテーション未設定 | 3.8 | 長期間同一鍵の使用 |
| Medium | EBS 暗号化未設定 | 2.2.1 | ボリュームデータの漏洩 |
| Medium | VPC Flow Logs 未設定 | 3.9 | ネットワーク監視不可 |
| Medium | GuardDuty 未有効化 | 4.15 | 脅威検出の欠如 |
| Medium | Secrets Manager のローテーション未設定 | - | 認証情報の固定化 |
| Low | デフォルト SG にルール残存 | 5.4 | 意図しないアクセス許可 |

## セキュリティチェックリスト

### IAM（CIS 1.x）
- [ ] ルートアカウントのアクセスキーが無効化されている
- [ ] ルートアカウントに MFA が設定されている
- [ ] 全 IAM ユーザーに MFA が設定されている
- [ ] アクセスキーが 90 日以内にローテーションされている
- [ ] パスワードポリシーが CIS 基準を満たしている
- [ ] インラインポリシーではなくグループポリシーを使用している
- [ ] 最小権限の原則が適用されている

### S3（CIS 2.1.x）
- [ ] アカウントレベルのパブリックアクセスブロックが有効
- [ ] 全バケットで暗号化が有効
- [ ] バケットのアクセスログが有効
- [ ] SSL 強制ポリシーが設定されている
- [ ] バージョニングが有効

### ネットワーク（CIS 5.x）
- [ ] SSH（22）が特定 IP に制限されている
- [ ] RDP（3389）が特定 IP に制限されている
- [ ] デフォルト Security Group にルールが残存していない
- [ ] VPC Flow Logs が有効
- [ ] 必要な VPC エンドポイントが設定されている

### ロギング・モニタリング（CIS 3.x / 4.x）
- [ ] CloudTrail がマルチリージョンで有効
- [ ] ログファイルの検証が有効
- [ ] CloudTrail ログの S3 バケットがパブリックでない
- [ ] GuardDuty が有効
- [ ] High 以上の GuardDuty 検出結果がない

### データ保護
- [ ] RDS の暗号化が有効
- [ ] EBS の暗号化がデフォルトで有効
- [ ] KMS キーのローテーションが有効
- [ ] Secrets Manager のローテーションが設定されている
- [ ] Lambda 環境変数にハードコードされたシークレットがない

### コンピュート
- [ ] EC2 で IMDSv2 が強制されている
- [ ] Lambda 関数が適切な VPC に配置されている
- [ ] ECS タスクが特権モードで実行されていない
- [ ] EKS のパブリックエンドポイントが制限されている
