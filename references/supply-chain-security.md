# Supply Chain Security Reference

ソフトウェアサプライチェーンの脆弱性検出と対策ガイド。

## SBOM（Software Bill of Materials）生成

### リスク

SBOM が未整備の場合、プロジェクトに含まれる全依存関係の把握が困難になり、脆弱性対応が遅れる。規制要件（米国大統領令 14028、EU CRA）への準拠にも必要。

### 検査パターン

```bash
# SBOM ファイルの存在確認
find . -maxdepth 3 -name '*.spdx*' -o -name '*.cdx*' -o -name 'bom.*' \
  -o -name 'sbom.*' 2>/dev/null | head -20

# CycloneDX / SPDX ツールの設定確認
grep -rn --include='package.json' \
  -E '(@cyclonedx|spdx-sbom-generator|syft|cdxgen)' .

# CI/CD での SBOM 生成ステップ確認
grep -rn --include='*.yml' --include='*.yaml' \
  -E '(cyclonedx|spdx|syft|cdxgen|sbom)' .github/ .gitlab-ci.yml 2>/dev/null
```

| ツール | 対応フォーマット | 対応言語 |
|--------|-----------------|----------|
| syft | CycloneDX, SPDX | 多言語対応 |
| cdxgen | CycloneDX | Node.js, Java, Python, Go |
| trivy sbom | CycloneDX, SPDX | コンテナ・ファイルシステム |

## Dependency Provenance（依存性の来歴）

### リスク

パッケージの公開元が正当であることを検証しない場合、改ざんされたパッケージを取り込むリスクがある。

### 検査パターン

```bash
# npm provenance 対応の確認
grep -rn '"provenance"' package.json .npmrc 2>/dev/null

# .npmrc のレジストリ設定確認
cat .npmrc 2>/dev/null | grep -E '(registry|@.*:registry)'

# SLSA provenance の検証設定
grep -rn --include='*.yml' --include='*.yaml' \
  -E '(slsa-verifier|cosign|sigstore|attest)' .github/ 2>/dev/null
```

| SLSA レベル | 要件 | 保護対象 |
|-------------|------|----------|
| Level 1 | ビルドプロセスの文書化 | ビルド元の可視性 |
| Level 2 | ホストされたビルドサービス | ビルド改ざん防止 |
| Level 3 | ビルド環境の分離 | ソース・ビルドの完全性 |
| Level 4 | 二者レビュー + 再現可能ビルド | 内部脅威防止 |

## Typosquatting（タイポスクワッティング）検出

### リスク

正規パッケージ名に酷似した悪意あるパッケージをインストールさせる攻撃。`lodash` → `lodahs`、`react` → `reactt` 等。

### 検査パターン

```bash
# package.json の全依存関係を抽出し確認
cat package.json | grep -E '"[^"]+":' | \
  grep -v -E '(name|version|description|scripts|devDependencies|dependencies|peerDependencies)'

# よくあるタイポスクワットパターンの検出（npm）
grep -E --include='package.json' \
  -i '(crossenv|cross-env\.|babelcli|babel-clli|event-stream|flatmap-stream)' package.json 2>/dev/null

# PyPI の typosquat 検出
grep -E '(python-dateutil|python_dateutil|dateuti1|requets|reqeusts)' \
  requirements*.txt setup.py pyproject.toml 2>/dev/null

# RubyGems の typosquat 検出
grep -E '(activesupport|active_suport|active-support)' Gemfile 2>/dev/null
```

**よくあるタイポスクワットパターン**:
- 文字の入れ替え: `lodash` → `lodahs`
- 文字の追加/削除: `colors` → `colour`
- ハイフン/アンダースコアの変更: `cross-env` → `crossenv`
- スコープの偽装: `@angular/core` → `angular-core`

## Lock File Integrity（ロックファイルの完全性）

### リスク

ロックファイルが改ざんされると、意図しないパッケージバージョンやレジストリからの取得が発生する。

### 検査パターン

```bash
# ロックファイルの存在確認
ls -la package-lock.json yarn.lock pnpm-lock.yaml Gemfile.lock \
  go.sum Cargo.lock poetry.lock 2>/dev/null

# package-lock.json 内の不審なレジストリ URL
grep -n '"resolved"' package-lock.json 2>/dev/null | \
  grep -v 'registry.npmjs.org' | head -20

# yarn.lock 内の不審なレジストリ URL
grep -n 'resolved "' yarn.lock 2>/dev/null | \
  grep -v 'registry.yarnpkg.com\|registry.npmjs.org' | head -20

# ロックファイルが Git 追跡されているか
git ls-files package-lock.json yarn.lock pnpm-lock.yaml \
  Gemfile.lock go.sum Cargo.lock 2>/dev/null

# lockfile-lint による検証（npm/yarn）
# npx lockfile-lint --path package-lock.json --type npm --allowed-hosts npm --validate-https
```

## Pre/Post Install Scripts（インストールスクリプト）

### リスク

npm の `preinstall` / `postinstall` スクリプトや pip の `setup.py` は、パッケージインストール時に任意のコードを実行できる。

### 検査パターン

```bash
# package.json の危険なスクリプト検出
grep -A 1 -E '"(preinstall|postinstall|preuninstall|postuninstall|prepare)"' \
  package.json node_modules/*/package.json 2>/dev/null | \
  grep -v 'node_modules/.package-lock' | head -30

# node_modules 内の postinstall スクリプト一覧
find node_modules -maxdepth 2 -name 'package.json' -exec \
  grep -l '"postinstall"' {} \; 2>/dev/null

# .npmrc で ignore-scripts の設定確認
grep 'ignore-scripts' .npmrc 2>/dev/null

# pip の setup.py 内の危険なコード
grep -rn --include='setup.py' \
  -E '(os\.system|subprocess|exec\(|eval\(|urllib|requests\.get)' . 2>/dev/null
```

## Dependency Confusion（依存性の混同）

### リスク

内部パッケージ名と同名のパッケージを公開レジストリに登録し、ビルドシステムに悪意あるパッケージを取得させる攻撃。

### 検査パターン

```bash
# スコープなしの内部パッケージの検出
grep -E '"[^@][^"]*":' package.json | \
  grep -v -E '(react|next|express|lodash|typescript|eslint|prettier|webpack|babel|jest)'

# .npmrc のスコープレジストリ設定
grep -E '@.*:registry' .npmrc 2>/dev/null

# pip の --extra-index-url（混同リスク）
grep -rn 'extra-index-url\|--index-url' pip.conf requirements*.txt \
  pyproject.toml setup.cfg 2>/dev/null

# Go のプライベートモジュール設定
grep 'GOPRIVATE\|GONOSUMDB\|GONOSUMCHECK' go.env .env* 2>/dev/null
cat go.env 2>/dev/null
```

**対策**:
- npm: `@org/` スコープを使用し、スコープレジストリを固定
- pip: `--index-url` のみ使用し `--extra-index-url` を避ける
- Go: `GOPRIVATE` を設定

## License Compliance（ライセンスコンプライアンス）

### リスク

GPL 等の Copyleft ライセンスのパッケージを含めると、プロジェクト全体にライセンス条件が波及する可能性がある。

### 検査パターン

```bash
# npm パッケージのライセンス一覧
npx license-checker --summary 2>/dev/null || \
  npx license-checker --csv 2>/dev/null | head -30

# GPL 系ライセンスの検出
npx license-checker --csv 2>/dev/null | grep -iE '(GPL|AGPL|LGPL|SSPL|EUPL)'

# pip のライセンス確認
pip-licenses --format=csv 2>/dev/null | grep -iE '(GPL|AGPL|LGPL|SSPL)'

# Go のライセンス確認
go-licenses csv ./... 2>/dev/null | grep -iE '(GPL|AGPL|LGPL)'
```

| ライセンス | 種別 | 商用利用時の注意 |
|-----------|------|-----------------|
| MIT / BSD / Apache-2.0 | Permissive | 制限少ない |
| LGPL-2.1 / LGPL-3.0 | Weak Copyleft | 動的リンクは許可 |
| GPL-2.0 / GPL-3.0 | Strong Copyleft | 派生物に GPL 適用必須 |
| AGPL-3.0 | Network Copyleft | SaaS 利用にも適用 |
| SSPL | Source Available | クラウドサービスに制限 |

## Vulnerability Scanning（脆弱性スキャン）

### 検査パターン

```bash
# npm audit（Node.js）
npm audit --json 2>/dev/null | head -50
npm audit --audit-level=high 2>/dev/null

# pip-audit（Python）
pip-audit --format=json 2>/dev/null | head -50

# cargo-audit（Rust）
cargo audit 2>/dev/null

# bundler-audit（Ruby）
bundle audit check --update 2>/dev/null

# govulncheck（Go）
govulncheck ./... 2>/dev/null

# CI/CD でのスキャン設定確認
grep -rn --include='*.yml' --include='*.yaml' \
  -E '(npm audit|pip-audit|cargo.audit|bundler-audit|govulncheck|trivy|snyk|dependabot)' \
  .github/ .gitlab-ci.yml 2>/dev/null

# Dependabot / Renovate の設定確認
cat .github/dependabot.yml 2>/dev/null
cat renovate.json renovate.json5 .renovaterc 2>/dev/null
```

## Version Pinning（バージョン固定とハッシュ検証）

### リスク

バージョン範囲指定（`^`, `~`, `*`）では、新しいバージョンに含まれる脆弱性を自動的に取り込むリスクがある。

### 検査パターン

```bash
# package.json のバージョン範囲指定検出
grep -E '"[^^~><=*]' package.json | grep -v -E '(name|version|description|scripts)' | head -5
grep -E '(\^|~|\*|>=|>)' package.json | grep -v 'node_modules' | head -20

# requirements.txt のピン留めなし検出
grep -v -E '(==|#|^$|^-r)' requirements.txt 2>/dev/null

# Gemfile のピン留めなし検出
grep -E "gem ['\"]" Gemfile 2>/dev/null | grep -v -E '(~>|>=|=)'

# go.mod の間接依存の確認
grep 'indirect' go.mod 2>/dev/null | wc -l

# pip の hash 検証モード
grep -E '(--require-hashes|hash=sha256)' requirements*.txt 2>/dev/null

# npm の package-lock.json integrity 確認
grep '"integrity"' package-lock.json 2>/dev/null | head -5
```

## サプライチェーンセキュリティチェックリスト

- [ ] SBOM が生成され、定期的に更新されている
- [ ] ロックファイルが Git で管理され、CI/CD で整合性検証されている
- [ ] 全依存パッケージが公式レジストリから取得されている
- [ ] 内部パッケージにスコープ（`@org/`）が設定されている
- [ ] npm/pip/gem のインストールスクリプトが検証されている
- [ ] 自動脆弱性スキャン（Dependabot / Renovate 等）が有効
- [ ] GPL/AGPL 等の Copyleft ライセンスが商用要件と矛盾していない
- [ ] バージョンがピン留めまたはロックファイルで固定されている
- [ ] CI/CD で `npm audit` / `pip-audit` 等が実行されている
- [ ] `.npmrc` で `ignore-scripts=true` が設定されている（必要に応じて例外追加）
- [ ] SLSA provenance または npm provenance が有効
- [ ] タイポスクワッティングチェックが定期的に実施されている
