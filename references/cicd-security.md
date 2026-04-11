# CI/CD Pipeline Security Reference

CI/CD パイプラインのセキュリティ検査ガイド。GitHub Actions、GitLab CI、Vercel を対象。

## GitHub Actions: サードパーティ Action のピンニング

### リスク

タグ（`v1`、`latest`）で指定された Action は、作成者がタグを移動させることで任意のコードを実行できる。SHA ピンニングが必須。

### 検査パターン

```bash
# SHA ピンニングされていない Action の検出
grep -rn --include='*.yml' --include='*.yaml' \
  'uses:' .github/workflows/ 2>/dev/null | \
  grep -v -E '(@[a-f0-9]{40}|actions/checkout|actions/setup-node)' | \
  grep -v '#'

# タグのみで指定された Action
grep -rn --include='*.yml' --include='*.yaml' \
  -E 'uses: [^@]+@v[0-9]' .github/workflows/ 2>/dev/null

# SHA ピンニングされた Action（Good）
grep -rn --include='*.yml' --include='*.yaml' \
  -E 'uses: .+@[a-f0-9]{40}' .github/workflows/ 2>/dev/null | head -10
```

## GITHUB_TOKEN の権限

### リスク

`GITHUB_TOKEN` のデフォルト権限が `write-all` の場合、侵害された Job がリポジトリを改ざんできる。

```bash
# permissions の設定確認
grep -rn --include='*.yml' --include='*.yaml' \
  -B 2 -A 10 'permissions:' .github/workflows/ 2>/dev/null

# permissions 未設定のワークフロー
for f in $(find .github/workflows -name '*.yml' -o -name '*.yaml' 2>/dev/null); do
  if ! grep -q 'permissions:' "$f"; then
    echo "NO PERMISSIONS DEFINED: $f"
  fi
done

# write-all の検出
grep -rn --include='*.yml' --include='*.yaml' \
  'permissions: write-all' .github/workflows/ 2>/dev/null
```

## Workflow Injection（ワークフローインジェクション）

### リスク

`${{ }}` 式にユーザー入力が直接展開されると、任意のコマンドが実行される。PR タイトル、Issue 本文、コミットメッセージ等が攻撃ベクトル。

### 検査パターン

```bash
# 危険な式の直接使用（Critical）
grep -rn --include='*.yml' --include='*.yaml' \
  -E '\$\{\{.*github\.(event\.(issue|pull_request|comment)\.(title|body|name)|head_ref)' \
  .github/workflows/ 2>/dev/null

# run: 内での ${{ }} 使用（インジェクションリスク）
grep -rn --include='*.yml' --include='*.yaml' \
  -B 1 -A 1 'run:.*\$\{\{' .github/workflows/ 2>/dev/null

# pull_request_target の使用（高リスク）
grep -rn --include='*.yml' --include='*.yaml' \
  'pull_request_target' .github/workflows/ 2>/dev/null

# workflow_run の使用（権限昇格リスク）
grep -rn --include='*.yml' --include='*.yaml' \
  'workflow_run' .github/workflows/ 2>/dev/null
```

**危険な式の例**:

| 式 | 攻撃ベクトル |
|----|-------------|
| `${{ github.event.issue.title }}` | Issue タイトルにコマンド注入 |
| `${{ github.event.pull_request.body }}` | PR 本文にコマンド注入 |
| `${{ github.event.comment.body }}` | コメントにコマンド注入 |
| `${{ github.head_ref }}` | ブランチ名にコマンド注入 |
| `${{ github.event.pages.*.page_name }}` | Wiki ページ名にコマンド注入 |

**対策**: 環境変数経由で値を渡し、直接展開しない。

```yaml
# BAD
- run: echo "${{ github.event.issue.title }}"

# GOOD
- run: echo "$TITLE"
  env:
    TITLE: ${{ github.event.issue.title }}
```

## Secret の露出

```bash
# secrets の使用箇所確認
grep -rn --include='*.yml' --include='*.yaml' \
  'secrets\.' .github/workflows/ 2>/dev/null

# echo/printf での secrets 出力（漏洩リスク）
grep -rn --include='*.yml' --include='*.yaml' \
  -E '(echo|printf).*\$\{\{.*secrets\.' .github/workflows/ 2>/dev/null

# secrets の環境変数への設定
grep -rn --include='*.yml' --include='*.yaml' \
  -A 3 'env:' .github/workflows/ 2>/dev/null | \
  grep 'secrets\.' | head -20

# $GITHUB_ENV への secrets 書き込み（全後続ステップに露出）
grep -rn --include='*.yml' --include='*.yaml' \
  'GITHUB_ENV.*secrets\|secrets.*GITHUB_ENV' .github/workflows/ 2>/dev/null
```

## Artifact Security

```bash
# upload-artifact / download-artifact の使用
grep -rn --include='*.yml' --include='*.yaml' \
  -E '(upload-artifact|download-artifact)' .github/workflows/ 2>/dev/null

# retention-days の設定確認
grep -rn --include='*.yml' --include='*.yaml' \
  'retention-days' .github/workflows/ 2>/dev/null

# 機密データを含む可能性のある artifact
grep -rn --include='*.yml' --include='*.yaml' \
  -A 5 'upload-artifact' .github/workflows/ 2>/dev/null | \
  grep -iE '(\.env|secret|credential|key|token|log)'
```

## Environment Protection

```bash
# environment の使用確認
grep -rn --include='*.yml' --include='*.yaml' \
  'environment:' .github/workflows/ 2>/dev/null

# 保護されていない production デプロイ
grep -rn --include='*.yml' --include='*.yaml' \
  -B 5 -A 5 'environment.*prod' .github/workflows/ 2>/dev/null
```

## OIDC（Workload Identity Federation）

### リスク

長期間有効なクレデンシャル（AWS Access Key 等）の代わりに、OIDC トークンで短期間の認証を行うべき。

```bash
# OIDC の使用確認
grep -rn --include='*.yml' --include='*.yaml' \
  -E '(id-token: write|aws-actions/configure-aws-credentials|google-github-actions/auth)' \
  .github/workflows/ 2>/dev/null

# 長期クレデンシャルの使用（OIDC 移行推奨）
grep -rn --include='*.yml' --include='*.yaml' \
  -E '(AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|GOOGLE_CREDENTIALS)' \
  .github/workflows/ 2>/dev/null
```

## Build Security

```bash
# ビルド時シークレットの露出
grep -rn --include='*.yml' --include='*.yaml' \
  -E '(build-args|--build-arg).*secrets\.' .github/workflows/ 2>/dev/null

# キャッシュポイズニングリスク
grep -rn --include='*.yml' --include='*.yaml' \
  -E '(actions/cache|cache:)' .github/workflows/ 2>/dev/null

# キャッシュキーにユーザー入力が含まれているか
grep -rn --include='*.yml' --include='*.yaml' \
  -A 5 'actions/cache' .github/workflows/ 2>/dev/null | \
  grep -E 'key:.*\$\{\{ github\.(event|head_ref)'
```

## Branch Protection

```bash
# branch protection の設定確認（gh CLI）
# gh api repos/{owner}/{repo}/branches/main/protection 2>/dev/null

# CODEOWNERS の存在確認
ls -la .github/CODEOWNERS CODEOWNERS docs/CODEOWNERS 2>/dev/null

# signed commits の設定確認
grep -rn --include='*.yml' --include='*.yaml' \
  'commit-signature' .github/ 2>/dev/null
```

## GitLab CI セキュリティ

```bash
# .gitlab-ci.yml の存在確認
cat .gitlab-ci.yml 2>/dev/null | head -50

# 保護されていない変数
grep -rn 'variables:' .gitlab-ci.yml 2>/dev/null

# 危険なスクリプト実行
grep -rn --include='.gitlab-ci.yml' \
  -E '(curl.*\| bash|wget.*\| sh|eval )' . 2>/dev/null

# Runner の設定確認
grep -rn 'tags:' .gitlab-ci.yml 2>/dev/null

# include で外部 CI 設定の取り込み
grep -rn 'include:' .gitlab-ci.yml 2>/dev/null
```

## Vercel セキュリティ

```bash
# vercel.json の確認
cat vercel.json 2>/dev/null

# ビルドコマンドの確認
grep -E '(buildCommand|installCommand|devCommand)' vercel.json 2>/dev/null

# 環境変数の設定
grep -E '(env|environment)' vercel.json 2>/dev/null

# ヘッダー設定の確認
grep -A 10 '"headers"' vercel.json 2>/dev/null

# Vercel preview デプロイのアクセス制御
grep -E '(password|protection|authentication)' vercel.json 2>/dev/null
```

## よくある設定ミス

| 深刻度 | 設定ミス | 影響 |
|--------|----------|------|
| Critical | `pull_request_target` で `actions/checkout` + PR コード実行 | リポジトリシークレット漏洩 |
| Critical | `${{ }}` 式にユーザー入力を直接展開 | 任意コマンド実行 |
| Critical | Secrets の echo 出力 | ログにシークレット漏洩 |
| High | Action を SHA ピンニングしていない | サプライチェーン攻撃 |
| High | GITHUB_TOKEN が write-all | リポジトリ改ざん |
| High | 長期クレデンシャルの使用（OIDC 未採用） | クレデンシャル漏洩時の影響大 |
| High | Environment protection 未設定 | 未承認デプロイ |
| Medium | Artifact に機密データ含有 | 公開リポジトリでアクセス可能 |
| Medium | キャッシュキーにユーザー入力 | キャッシュポイズニング |
| Low | retention-days 未設定 | 不要な artifact の残存 |

## CI/CD セキュリティチェックリスト

- [ ] 全サードパーティ Action が SHA でピンニングされている
- [ ] `permissions:` がワークフローまたはジョブレベルで最小権限に設定されている
- [ ] `${{ }}` 式にユーザー入力が直接展開されていない
- [ ] `pull_request_target` が安全に使用されている（PR コードの checkout を避ける）
- [ ] Secrets が `echo` / `printf` で出力されていない
- [ ] `$GITHUB_ENV` に secrets が書き込まれていない
- [ ] Environment protection（required reviewers）が本番デプロイに設定されている
- [ ] OIDC が使用され、長期クレデンシャルが排除されている
- [ ] Branch protection（required reviews, status checks）が有効
- [ ] CODEOWNERS が設定されている
- [ ] Artifact に機密データが含まれていない
- [ ] `curl | bash` パターンが使用されていない
- [ ] Vercel preview デプロイにアクセス制御が設定されている
- [ ] GitLab CI の変数が protected / masked に設定されている
