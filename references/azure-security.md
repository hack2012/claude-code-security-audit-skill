# Azure Security Testing Reference

Azure Security Benchmark に基づくセキュリティ検査ガイド。
az CLI コマンドによる自動検査と CIS Microsoft Azure Foundations Benchmark への準拠を確認する。

## Azure AD / Entra ID の検査

### Conditional Access・MFA

```bash
# Conditional Access ポリシー一覧
az ad conditionalaccess policy list \
  --query '[].{name:displayName, state:state, grantControls:grantControls}' 2>/dev/null

# MFA が要求されるポリシーの確認
az ad conditionalaccess policy list \
  --query '[?grantControls.builtInControls[?contains(@, `mfa`)]].displayName' 2>/dev/null

# 全ユーザーの MFA 状態確認
az ad user list --query '[].{UPN:userPrincipalName, MFA:strongAuthenticationDetail}' 2>/dev/null
```

### Privileged Identity Management (PIM)

```bash
# グローバル管理者ロールのメンバー（CIS 1.1）
az role assignment list --role "Owner" --all \
  --query '[].{principal:principalName, scope:scope}'

# 永続的な特権ロール割り当て
az role assignment list --all \
  --query '[?roleDefinitionName==`Owner` || roleDefinitionName==`Contributor`].{principal:principalName, role:roleDefinitionName, scope:scope}'

# カスタムロールの確認
az role definition list --custom-role-only true \
  --query '[].{name:roleName, permissions:permissions[].actions}'
```

### アプリケーション登録

```bash
# アプリケーション登録の一覧
az ad app list --all \
  --query '[].{appId:appId, displayName:displayName, signInAudience:signInAudience}'

# 期限切れまたは期限間近のクライアントシークレット
az ad app list --all --query '[].{appId:appId, name:displayName, credentials:passwordCredentials[].{endDate:endDateTime}}' 2>/dev/null

# マルチテナントアプリケーション（signInAudience が AzureADMultipleOrgs）
az ad app list --all \
  --query '[?signInAudience==`AzureADMultipleOrgs`].{appId:appId, name:displayName}'

# 過度な API アクセス許可を持つアプリ
az ad app list --all \
  --query '[].{appId:appId, name:displayName, requiredResourceAccess:requiredResourceAccess}'
```

## Storage の検査

### ストレージアカウント

```bash
# ストレージアカウント一覧
az storage account list \
  --query '[].{name:name, sku:sku.name, httpsOnly:enableHttpsTrafficOnly, minTls:minimumTlsVersion}'

# HTTPS 強制の確認（CIS 3.1）
az storage account list \
  --query '[?enableHttpsTrafficOnly==`false`].name'

# TLS バージョンの確認（CIS 3.15 - TLS 1.2 以上）
az storage account list \
  --query '[?minimumTlsVersion!=`TLS1_2`].{name:name, tls:minimumTlsVersion}'

# Blob のパブリックアクセス確認（CIS 3.5）
az storage account list \
  --query '[?allowBlobPublicAccess==`true`].name'

# ストレージアカウントのネットワークルール
for account in $(az storage account list --query '[].name' -o tsv); do
  echo "=== $account ==="
  az storage account show --name "$account" \
    --query 'networkRuleSet.{defaultAction:defaultAction, ipRules:ipRules, virtualNetworkRules:virtualNetworkRules}'
done

# ストレージアカウントの暗号化設定
az storage account list \
  --query '[].{name:name, encryption:encryption.services}'
```

### SAS トークン・アクセスキー

```bash
# ストレージアカウントキーの一覧（ローテーション確認）
for account in $(az storage account list --query '[].name' -o tsv); do
  echo "=== $account ==="
  az storage account keys list --account-name "$account" \
    --query '[].{keyName:keyName, creationTime:creationTime}'
done

# Shared Key アクセスの無効化確認（推奨）
az storage account list \
  --query '[?allowSharedKeyAccess!=`false`].name'
```

## NSG（Network Security Group）の検査

```bash
# NSG の一覧
az network nsg list \
  --query '[].{name:name, rg:resourceGroup, rules:securityRules[].{name:name, access:access, direction:direction, sourceAddr:sourceAddressPrefix, destPort:destinationPortRange, priority:priority}}'

# 全ポート許可の NSG ルール
az network nsg list --query '[].securityRules[?sourceAddressPrefix==`*` && access==`Allow` && direction==`Inbound`].{nsg:id, name:name, destPort:destinationPortRange, priority:priority}' -o table

# SSH（22）が全公開の NSG ルール（CIS 6.1）
az network nsg list \
  --query '[].securityRules[?sourceAddressPrefix==`*` && destinationPortRange==`22` && access==`Allow` && direction==`Inbound`].{name:name, priority:priority}'

# RDP（3389）が全公開の NSG ルール（CIS 6.2）
az network nsg list \
  --query '[].securityRules[?sourceAddressPrefix==`*` && destinationPortRange==`3389` && access==`Allow` && direction==`Inbound`].{name:name, priority:priority}'

# NSG Flow Logs の確認（CIS 6.4）
az network watcher flow-log list \
  --query '[].{name:name, enabled:enabled, nsg:targetResourceId, retention:retentionPolicy}' 2>/dev/null
```

## Key Vault の検査

```bash
# Key Vault 一覧
az keyvault list \
  --query '[].{name:name, sku:properties.sku.name, softDelete:properties.enableSoftDelete, purgeProtection:properties.enablePurgeProtection}'

# ソフトデリート未有効化の Key Vault（CIS 8.4）
az keyvault list \
  --query '[?properties.enableSoftDelete!=`true`].name'

# パージ保護未有効化の Key Vault（CIS 8.5）
az keyvault list \
  --query '[?properties.enablePurgeProtection!=`true`].name'

# Key Vault のアクセスポリシー確認
for vault in $(az keyvault list --query '[].name' -o tsv); do
  echo "=== $vault ==="
  az keyvault show --name "$vault" \
    --query 'properties.accessPolicies[].{objectId:objectId, permissions:permissions}'
done

# Key Vault のネットワークルール
for vault in $(az keyvault list --query '[].name' -o tsv); do
  az keyvault show --name "$vault" \
    --query 'properties.networkAcls.{defaultAction:defaultAction, ipRules:ipRules}'
done

# キーのローテーション状態
for vault in $(az keyvault list --query '[].name' -o tsv); do
  echo "=== $vault ==="
  az keyvault key list --vault-name "$vault" \
    --query '[].{name:name, enabled:attributes.enabled, expires:attributes.expires, created:attributes.created}' 2>/dev/null
done
```

## App Service の検査

```bash
# App Service 一覧
az webapp list \
  --query '[].{name:name, rg:resourceGroup, httpsOnly:httpsOnly, state:state}'

# HTTPS 強制の確認（CIS 9.2）
az webapp list \
  --query '[?httpsOnly==`false`].name'

# マネージド ID の確認
az webapp list \
  --query '[].{name:name, identity:identity.type}'

# 認証設定の確認（CIS 9.1）
for app in $(az webapp list --query '[].name' -o tsv); do
  rg=$(az webapp show --name "$app" --query 'resourceGroup' -o tsv)
  az webapp auth show --name "$app" --resource-group "$rg" \
    --query '{enabled:enabled, defaultProvider:defaultProvider}' 2>/dev/null
done

# TLS バージョンの確認（CIS 9.3）
for app in $(az webapp list --query '[].name' -o tsv); do
  rg=$(az webapp show --name "$app" --query 'resourceGroup' -o tsv)
  az webapp config show --name "$app" --resource-group "$rg" \
    --query '{minTlsVersion:minTlsVersion, ftpsState:ftpsState, http20Enabled:http20Enabled}'
done

# クライアント証明書の確認
az webapp list \
  --query '[].{name:name, clientCertEnabled:clientCertEnabled}'
```

## SQL Database の検査

```bash
# SQL Server 一覧
az sql server list \
  --query '[].{name:name, rg:resourceGroup, adminLogin:administratorLogin, minTls:minimalTlsVersion}'

# ファイアウォールルールの確認（CIS 4.1.1）
for server in $(az sql server list --query '[].name' -o tsv); do
  rg=$(az sql server show --name "$server" --query 'resourceGroup' -o tsv)
  echo "=== $server ==="
  az sql server firewall-rule list --server "$server" --resource-group "$rg" \
    --query '[].{name:name, startIp:startIpAddress, endIp:endIpAddress}'
done

# 0.0.0.0 - 255.255.255.255 のルール検出
for server in $(az sql server list --query '[].name' -o tsv); do
  rg=$(az sql server show --name "$server" --query 'resourceGroup' -o tsv)
  az sql server firewall-rule list --server "$server" --resource-group "$rg" \
    --query '[?startIpAddress==`0.0.0.0` && endIpAddress==`255.255.255.255`].name'
done

# TDE（Transparent Data Encryption）の確認（CIS 4.1.2）
for server in $(az sql server list --query '[].name' -o tsv); do
  rg=$(az sql server show --name "$server" --query 'resourceGroup' -o tsv)
  for db in $(az sql db list --server "$server" --resource-group "$rg" --query '[].name' -o tsv); do
    az sql db tde show --server "$server" --database "$db" --resource-group "$rg" \
      --query '{database:databaseName, status:status}' 2>/dev/null
  done
done

# 監査設定の確認（CIS 4.1.3）
for server in $(az sql server list --query '[].name' -o tsv); do
  rg=$(az sql server show --name "$server" --query 'resourceGroup' -o tsv)
  az sql server audit-policy show --server "$server" --resource-group "$rg" \
    --query '{state:state, retentionDays:retentionDays}' 2>/dev/null
done

# AAD 管理者の確認（CIS 4.1.4）
for server in $(az sql server list --query '[].name' -o tsv); do
  rg=$(az sql server show --name "$server" --query 'resourceGroup' -o tsv)
  az sql server ad-admin list --server "$server" --resource-group "$rg" 2>/dev/null
done
```

## AKS の検査

```bash
# AKS クラスタ一覧
az aks list \
  --query '[].{name:name, rg:resourceGroup, rbac:enableRbac, networkPolicy:networkProfile.networkPolicy}'

# RBAC 未有効化のクラスタ（CIS 8.5）
az aks list \
  --query '[?enableRbac==`false`].name'

# Azure AD 統合の確認
az aks list \
  --query '[].{name:name, aadProfile:aadProfile}'

# ネットワークポリシーの確認
az aks list \
  --query '[?networkProfile.networkPolicy==`null`].name'

# API サーバーの認可 IP 範囲
az aks list \
  --query '[].{name:name, authorizedIpRanges:apiServerAccessProfile.authorizedIpRanges}'

# ポッドセキュリティの確認
az aks list \
  --query '[].{name:name, podSecurityPolicy:podSecurityPolicy}'
```

## Functions の検査

```bash
# Function App 一覧
az functionapp list \
  --query '[].{name:name, rg:resourceGroup, httpsOnly:httpsOnly, identity:identity.type}'

# 認証設定の確認
for app in $(az functionapp list --query '[].name' -o tsv); do
  rg=$(az functionapp show --name "$app" --query 'resourceGroup' -o tsv)
  az functionapp auth show --name "$app" --resource-group "$rg" \
    --query '{enabled:enabled}' 2>/dev/null
done

# HTTPS 強制の確認
az functionapp list \
  --query '[?httpsOnly==`false`].name'

# マネージド ID の使用確認
az functionapp list \
  --query '[?identity.type==`null`].name'
```

## Monitor・Diagnostic Settings の検査

```bash
# サブスクリプションレベルの Activity Log アラート（CIS 5.2.x）
az monitor activity-log alert list \
  --query '[].{name:name, enabled:enabled, scopes:scopes, condition:condition}'

# リソースの Diagnostic Settings 確認
az monitor diagnostic-settings list --resource <RESOURCE_ID> \
  --query '[].{name:name, logs:logs[].{category:category, enabled:enabled}, metrics:metrics[].{category:category, enabled:enabled}}' 2>/dev/null

# Log Analytics Workspace の一覧
az monitor log-analytics workspace list \
  --query '[].{name:name, rg:resourceGroup, retention:retentionInDays, sku:sku.name}'

# 保持期間の確認（CIS 5.1.2 - 90 日以上推奨）
az monitor log-analytics workspace list \
  --query '[?retentionInDays < `90`].{name:name, retention:retentionInDays}'
```

## Defender for Cloud の検査

```bash
# Secure Score の確認
az security secure-score list \
  --query '[].{name:displayName, current:score.current, max:score.max, percentage:score.percentage}'

# セキュリティ推奨事項（High 以上）
az security assessment list \
  --query '[?status.code==`Unhealthy` && (properties.metadata.severity==`High` || properties.metadata.severity==`Critical`)].{name:displayName, severity:properties.metadata.severity, status:status.code}' 2>/dev/null

# Defender プランの有効化状態
az security pricing list \
  --query '[].{name:name, tier:pricingTier}'

# 各プランが Standard（有効）であることを確認
az security pricing list \
  --query '[?pricingTier==`Free`].name'
```

## Private Endpoints の検査

```bash
# Private Endpoint 一覧
az network private-endpoint list \
  --query '[].{name:name, rg:resourceGroup, subnet:subnet.id, connections:privateLinkServiceConnections[].{service:privateLinkServiceId, status:privateLinkServiceConnectionState.status}}'

# Private Link が未設定のリソース確認（ストレージ）
for account in $(az storage account list --query '[].name' -o tsv); do
  pe=$(az storage account show --name "$account" --query 'privateEndpointConnections' -o tsv)
  [ -z "$pe" ] && echo "NO PRIVATE ENDPOINT: $account"
done

# Private DNS Zone の確認
az network private-dns zone list \
  --query '[].{name:name, numberOfRecordSets:numberOfRecordSets}'
```

## コードベースの静的解析

```bash
# Azure 認証情報のハードコード検出
grep -rn --include='*.{ts,tsx,js,jsx,py,go,java,cs}' \
  -iE '(azure_client_secret|azure_tenant_id|DefaultEndpointsProtocol)' . | grep -v node_modules

# SAS トークンのハードコード
grep -rn --include='*.{ts,tsx,js,jsx,py,go,java,cs}' \
  -E '(sv=|sig=|se=|sp=).*(&sv=|&sig=|&se=|&sp=)' . | grep -v node_modules

# 接続文字列のハードコード
grep -rn --include='*.{ts,tsx,js,jsx,py,go,java,cs}' \
  -E '(AccountKey=|SharedAccessKey=|Password=)[A-Za-z0-9+/=]{10,}' . | grep -v node_modules

# .env ファイル内の Azure 認証情報
grep -rn -iE '(AZURE_CLIENT_SECRET|AZURE_STORAGE_KEY|AZURE_SQL_PASSWORD)' .env* 2>/dev/null
```

## よくある設定ミス

| 深刻度 | 設定ミス | CIS | 影響 |
|--------|----------|-----|------|
| Critical | NSG で全ポートが * から許可 | 6.1 | 全サービスが外部露出 |
| Critical | SQL Server の全 IP 許可ファイアウォール | 4.1.1 | データベースへの直接アクセス |
| Critical | Storage Account のパブリック Blob アクセス | 3.5 | データの全公開 |
| Critical | 認証情報のハードコード | - | 認証情報の漏洩 |
| High | Key Vault のソフトデリート未有効化 | 8.4 | シークレットの永久削除リスク |
| High | App Service の HTTPS 未強制 | 9.2 | 通信の盗聴 |
| High | SQL Database の TDE 未有効化 | 4.1.2 | 保存データの平文露出 |
| High | Defender for Cloud の Free プラン | - | 脅威検出の欠如 |
| High | MFA の Conditional Access 未設定 | 1.1 | アカウント乗っ取りリスク |
| Medium | NSG Flow Logs 未有効化 | 6.4 | ネットワーク監視不可 |
| Medium | AKS の RBAC 未有効化 | - | Kubernetes アクセス制御の欠如 |
| Medium | Log Analytics の保持期間不足 | 5.1.2 | 監査証跡の喪失 |
| Medium | マネージド ID 未使用 | - | 認証情報管理の複雑化 |
| Low | Storage Account の TLS 1.2 未強制 | 3.15 | 古いプロトコルの使用 |
| Low | Private Endpoint 未設定 | - | パブリックネットワーク経由のアクセス |

## セキュリティチェックリスト

### Azure AD / Entra ID（CIS 1.x）
- [ ] Conditional Access ポリシーで MFA が要求されている
- [ ] グローバル管理者が最小限のメンバーに制限されている
- [ ] PIM で特権ロールが Just-In-Time 化されている
- [ ] アプリケーション登録のシークレットが有効期限内
- [ ] マルチテナントアプリが必要最小限

### Storage（CIS 3.x）
- [ ] HTTPS 転送が強制されている
- [ ] 最小 TLS バージョンが 1.2 以上
- [ ] Blob のパブリックアクセスが無効
- [ ] ネットワークルールでデフォルトアクションが Deny
- [ ] Shared Key アクセスが無効化されている

### ネットワーク（CIS 6.x）
- [ ] NSG で SSH（22）が特定 IP に制限されている
- [ ] NSG で RDP（3389）が特定 IP に制限されている
- [ ] NSG Flow Logs が有効
- [ ] Private Endpoint が適切に設定されている

### Key Vault（CIS 8.x）
- [ ] ソフトデリートが有効
- [ ] パージ保護が有効
- [ ] アクセスポリシーが最小権限
- [ ] ネットワークルールが設定されている
- [ ] キーのローテーションが設定されている

### App Service（CIS 9.x）
- [ ] HTTPS が強制されている
- [ ] マネージド ID が使用されている
- [ ] 認証が有効化されている
- [ ] 最小 TLS バージョンが 1.2 以上
- [ ] FTPS が無効化されている

### SQL Database（CIS 4.1.x）
- [ ] ファイアウォールルールに全 IP 許可がない
- [ ] TDE が有効
- [ ] 監査が有効
- [ ] AAD 管理者が設定されている
- [ ] 最小 TLS バージョンが 1.2 以上

### モニタリング（CIS 5.x）
- [ ] Activity Log アラートが設定されている
- [ ] Diagnostic Settings が適切に構成されている
- [ ] Log Analytics の保持期間が 90 日以上
- [ ] Defender for Cloud が Standard プラン

### コンテナ
- [ ] AKS で RBAC が有効
- [ ] Azure AD 統合が設定されている
- [ ] ネットワークポリシーが設定されている
- [ ] API サーバーの認可 IP 範囲が制限されている
