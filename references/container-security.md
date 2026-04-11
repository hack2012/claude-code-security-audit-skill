# Container & Kubernetes Security Reference

コンテナと Kubernetes 環境のセキュリティ検査ガイド。

## Dockerfile セキュリティ

### root ユーザーでの実行

コンテナが root で実行されると、コンテナエスケープ時にホストの root 権限を取得されるリスクがある。

```bash
# USER 指令の確認（未指定は root 実行）
grep -rn 'USER ' Dockerfile* docker/Dockerfile* 2>/dev/null

# USER 指令がないファイルの検出
for f in $(find . -name 'Dockerfile*' -not -path '*/node_modules/*' 2>/dev/null); do
  if ! grep -q '^USER ' "$f"; then
    echo "NO USER DIRECTIVE: $f"
  fi
done

# root として明示的に実行しているケース
grep -rn 'USER root' Dockerfile* 2>/dev/null
```

### latest タグの使用

`latest` タグはイミュータブルでないため、再現性がなく、改ざんされたイメージを取得するリスクがある。

```bash
# latest タグまたはタグなしの FROM 検出
grep -rn '^FROM' Dockerfile* 2>/dev/null | \
  grep -E '(:latest|[^:]+$)' | grep -v -E ':[0-9]+\.'

# docker-compose.yml での latest 使用
grep -rn 'image:' docker-compose*.yml 2>/dev/null | \
  grep -E '(:latest|[^:]+$)' | grep -v -E ':[0-9]+\.'
```

### Secrets in Layers

Docker ビルド時にコピーされたシークレットは、削除してもイメージレイヤーに残る。

```bash
# シークレットファイルのコピー検出
grep -rn --include='Dockerfile*' \
  -E '(COPY|ADD).*(\.env|\.key|\.pem|credentials|secret|password|token|id_rsa)' . 2>/dev/null

# ARG/ENV でのシークレット設定
grep -rn --include='Dockerfile*' \
  -iE '(ARG|ENV).*(PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE_KEY|CREDENTIAL)' . 2>/dev/null

# Docker BuildKit の --mount=type=secret の使用確認
grep -rn 'mount=type=secret' Dockerfile* 2>/dev/null
```

### Multi-stage Build

```bash
# Multi-stage build の使用確認
grep -c '^FROM' Dockerfile* 2>/dev/null | grep -v ':1$'

# 最終ステージのベースイメージ確認
for f in $(find . -name 'Dockerfile*' -not -path '*/node_modules/*' 2>/dev/null); do
  echo "=== $f ==="
  grep '^FROM' "$f" | tail -1
done
```

### .dockerignore

```bash
# .dockerignore の存在確認
ls -la .dockerignore 2>/dev/null

# .dockerignore に機密ファイルが含まれているか
grep -E '(\.env|\.git|node_modules|\.ssh|\.aws|credentials)' \
  .dockerignore 2>/dev/null
```

## Image Scanning（イメージスキャン）

### 検査パターン

```bash
# Trivy によるスキャン設定確認
grep -rn --include='*.yml' --include='*.yaml' \
  -E '(trivy|aquasecurity/trivy|grype|docker scout|snyk container)' \
  .github/ .gitlab-ci.yml 2>/dev/null

# trivy.yaml 設定確認
cat .trivy.yaml trivy.yaml 2>/dev/null
```

| ツール | 特徴 | 統合方法 |
|--------|------|----------|
| Trivy | OSS、高速、多言語対応 | CI/CD、GitHub Actions |
| Grype | OSS、SBOM 連携 | CI/CD |
| Docker Scout | Docker 公式、SBOM 自動生成 | Docker Desktop |
| Snyk Container | 商用、修正提案あり | CI/CD、IDE |

## Kubernetes RBAC

### リスク

過剰な RBAC 権限は、Pod が侵害された際の特権昇格リスクを増大させる。

```bash
# ClusterRole の過度な権限（ワイルドカード）
grep -rn --include='*.yaml' --include='*.yml' \
  -A 5 'kind: ClusterRole' . 2>/dev/null | grep -E '(\*|cluster-admin)'

# ClusterRoleBinding の検出
grep -rn --include='*.yaml' --include='*.yml' \
  'kind: ClusterRoleBinding' . 2>/dev/null

# ServiceAccount へのクラスタ管理者権限付与
grep -rn --include='*.yaml' --include='*.yml' \
  -B 5 -A 10 'roleRef' . 2>/dev/null | grep -E '(cluster-admin|name:.*admin)'

# default ServiceAccount の使用検出
grep -rn --include='*.yaml' --include='*.yml' \
  'serviceAccountName: default' . 2>/dev/null
```

## Pod Security

### SecurityContext の検査

```bash
# SecurityContext の設定確認
grep -rn --include='*.yaml' --include='*.yml' \
  -A 10 'securityContext' . 2>/dev/null | head -50

# privileged コンテナの検出（Critical）
grep -rn --include='*.yaml' --include='*.yml' \
  'privileged: true' . 2>/dev/null

# runAsNonRoot の未設定検出
for f in $(find . -name '*.yaml' -o -name '*.yml' | \
  xargs grep -l 'kind: Pod\|kind: Deployment\|kind: StatefulSet' 2>/dev/null); do
  if ! grep -q 'runAsNonRoot: true' "$f"; then
    echo "NO runAsNonRoot: $f"
  fi
done

# readOnlyRootFilesystem の未設定検出
for f in $(find . -name '*.yaml' -o -name '*.yml' | \
  xargs grep -l 'kind: Pod\|kind: Deployment\|kind: StatefulSet' 2>/dev/null); do
  if ! grep -q 'readOnlyRootFilesystem: true' "$f"; then
    echo "NO readOnlyRootFilesystem: $f"
  fi
done

# capabilities の DROP ALL 確認
grep -rn --include='*.yaml' --include='*.yml' \
  -A 3 'capabilities' . 2>/dev/null | grep -E '(drop|ALL)'

# hostNetwork / hostPID / hostIPC の使用検出
grep -rn --include='*.yaml' --include='*.yml' \
  -E '(hostNetwork|hostPID|hostIPC): true' . 2>/dev/null
```

## Network Policies

### リスク

NetworkPolicy が未設定の場合、クラスタ内の全 Pod 間で無制限に通信が可能。

```bash
# NetworkPolicy の存在確認
grep -rn --include='*.yaml' --include='*.yml' \
  'kind: NetworkPolicy' . 2>/dev/null

# default deny ポリシーの確認
grep -rn --include='*.yaml' --include='*.yml' \
  -A 15 'kind: NetworkPolicy' . 2>/dev/null | grep -E '(Ingress|Egress|podSelector: {})'

# Namespace ごとの NetworkPolicy 確認
grep -rn --include='*.yaml' --include='*.yml' \
  -B 5 'kind: NetworkPolicy' . 2>/dev/null | grep 'namespace:'
```

## Kubernetes Secrets

### リスク

Kubernetes Secrets は Base64 エンコードのみで、暗号化されていない。etcd に平文で保存される場合がある。

```bash
# Secret マニフェストの検出
grep -rn --include='*.yaml' --include='*.yml' \
  'kind: Secret' . 2>/dev/null

# Secret の値がハードコードされている検出
grep -rn --include='*.yaml' --include='*.yml' \
  -A 10 'kind: Secret' . 2>/dev/null | grep -E '(data:|stringData:)' -A 5

# ExternalSecrets / SealedSecrets の使用確認
grep -rn --include='*.yaml' --include='*.yml' \
  -E '(ExternalSecret|SealedSecret|SecretStore|ClusterSecretStore)' . 2>/dev/null

# Secret が Git 追跡されていないか
git ls-files | grep -iE '(secret|credential).*\.(yaml|yml)$'
```

## Registry セキュリティ

```bash
# イメージ参照の確認（プライベートレジストリか）
grep -rn --include='*.yaml' --include='*.yml' --include='Dockerfile*' \
  -E '(image:|FROM)' . 2>/dev/null | \
  grep -v -E '(gcr\.io|\.ecr\.|\.azurecr\.|ghcr\.io|registry\.)' | head -20

# imagePullPolicy の確認
grep -rn --include='*.yaml' --include='*.yml' \
  'imagePullPolicy' . 2>/dev/null

# イメージ署名の検証設定（cosign / Notary）
grep -rn --include='*.yaml' --include='*.yml' \
  -E '(cosign|notary|connaisseur|kyverno.*verifyImages)' . 2>/dev/null
```

## Resource Limits

### リスク

リソース制限が未設定の場合、Pod がノードのリソースを枯渇させ、DoS を引き起こす可能性がある。

```bash
# resources の設定確認
grep -rn --include='*.yaml' --include='*.yml' \
  -A 8 'resources:' . 2>/dev/null | head -40

# limits が未設定のコンテナ検出
for f in $(find . -name '*.yaml' -o -name '*.yml' | \
  xargs grep -l 'kind: Deployment\|kind: StatefulSet\|kind: DaemonSet' 2>/dev/null); do
  if ! grep -q 'limits:' "$f"; then
    echo "NO RESOURCE LIMITS: $f"
  fi
done

# LimitRange の確認
grep -rn --include='*.yaml' --include='*.yml' \
  'kind: LimitRange' . 2>/dev/null
```

## Service Mesh セキュリティ

```bash
# Istio / Linkerd の設定確認
grep -rn --include='*.yaml' --include='*.yml' \
  -E '(istio|linkerd|PeerAuthentication|AuthorizationPolicy)' . 2>/dev/null

# mTLS の設定確認
grep -rn --include='*.yaml' --include='*.yml' \
  -A 5 'PeerAuthentication' . 2>/dev/null | grep -E '(STRICT|PERMISSIVE|DISABLE)'

# mTLS が PERMISSIVE（非強制）の検出
grep -rn --include='*.yaml' --include='*.yml' \
  'mode: PERMISSIVE' . 2>/dev/null
```

## よくある設定ミス

| 深刻度 | 設定ミス | 影響 |
|--------|----------|------|
| Critical | `privileged: true` のコンテナ | コンテナエスケープでホスト root 取得 |
| Critical | ClusterRole に `*` 権限 | クラスタ全体の制御が可能 |
| Critical | Secret が Git にコミット | 全クレデンシャルの漏洩 |
| High | root ユーザーでの実行 | コンテナ内の権限昇格 |
| High | latest タグの使用 | 再現性の欠如、改ざんリスク |
| High | NetworkPolicy 未設定 | Pod 間の無制限通信 |
| High | Resource Limits 未設定 | DoS リスク |
| Medium | readOnlyRootFilesystem 未設定 | 永続的なマルウェア配置 |
| Medium | .dockerignore 未設定 | ビルドコンテキストに機密ファイル含有 |
| Medium | mTLS が PERMISSIVE | 通信の盗聴リスク |
| Low | imagePullPolicy: Always 未設定 | キャッシュされた古いイメージ使用 |

## コンテナ・Kubernetes セキュリティチェックリスト

- [ ] 全 Dockerfile に `USER` 指令があり、非 root で実行されている
- [ ] イメージタグが specific version で固定されている（`latest` 未使用）
- [ ] Multi-stage build で最終イメージが最小化されている
- [ ] `.dockerignore` に `.env`、`.git`、`node_modules` 等が含まれている
- [ ] BuildKit の `--mount=type=secret` でシークレットが注入されている
- [ ] CI/CD でイメージスキャン（Trivy / Grype）が実行されている
- [ ] Pod に `securityContext` が設定されている（runAsNonRoot, readOnlyRootFilesystem）
- [ ] `privileged: true` のコンテナが存在しない
- [ ] capabilities が `drop: ["ALL"]` で最小化されている
- [ ] NetworkPolicy で default deny が設定されている
- [ ] Kubernetes Secrets が外部シークレットマネージャーと連携している
- [ ] RBAC がワイルドカード権限を使用していない
- [ ] Resource Limits（CPU / Memory）が全コンテナに設定されている
- [ ] Service Mesh の mTLS が STRICT モードで設定されている
- [ ] イメージの署名・検証（cosign 等）が有効になっている
