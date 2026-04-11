# Go Security Testing Reference

Go 固有の脆弱性パターンと検査ガイド。goroutine 安全性、unsafe パッケージ、Web フレームワーク対応。

## SQL Injection

### リスク

`database/sql` パッケージの `Query()` / `Exec()` に文字列結合で SQL を渡すと SQL Injection が発生する。GORM や sqlx でも raw クエリ使用時は同様のリスクがある。

### 検査パターン

```bash
# 文字列結合による SQL 構築
grep -rn --include='*.go' \
  -E '(db\.(Query|Exec|QueryRow)\(.*(\+|fmt\.Sprintf|fmt\.Fprintf))' . | grep -v vendor

# GORM raw クエリ
grep -rn --include='*.go' -E '(\.Raw\(|\.Exec\().*(\+|fmt\.Sprintf)' . | grep -v vendor

# sqlx raw クエリ
grep -rn --include='*.go' -E '(sqlx\.(Get|Select|Exec)|\.NamedExec)' . | grep -v vendor

# fmt.Sprintf で SQL 構築（危険）
grep -rn --include='*.go' 'fmt\.Sprintf.*SELECT\|fmt\.Sprintf.*INSERT\|fmt\.Sprintf.*UPDATE\|fmt\.Sprintf.*DELETE' . | grep -v vendor

# プレースホルダの確認（安全なパターン）
grep -rn --include='*.go' -E '(db\.(Query|Exec|QueryRow)\(.*\$[0-9]|\?)' . | grep -v vendor
```

## Command Injection

### リスク

`os/exec` パッケージや `syscall` による外部コマンド実行にユーザー入力が含まれると任意コマンド実行が可能。

### 検査パターン

```bash
# os/exec の使用
grep -rn --include='*.go' -E '(exec\.Command\(|exec\.CommandContext\()' . | grep -v vendor

# syscall.Exec の使用
grep -rn --include='*.go' 'syscall\.Exec' . | grep -v vendor

# ユーザー入力がコマンドに渡されるパターン
grep -rn --include='*.go' -E 'exec\.Command\(.*r\.(Form|URL|Body|Header)' . | grep -v vendor

# sh -c による shell 経由の実行（特に危険）
grep -rn --include='*.go' -E 'exec\.Command\("(sh|bash|cmd)"' . | grep -v vendor
```

## Path Traversal

### リスク

`filepath.Join()` はパストラバーサルを防止しない（`../` を正規化するが、結合結果が意図したディレクトリ外を指す可能性がある）。

### 検査パターン

```bash
# filepath.Join にユーザー入力を使用
grep -rn --include='*.go' -E 'filepath\.Join\(.*r\.(Form|URL|Param)' . | grep -v vendor

# os.Open / os.ReadFile にユーザー入力
grep -rn --include='*.go' -E '(os\.Open|os\.ReadFile|ioutil\.ReadFile)\(' . | grep -v vendor

# http.ServeFile（パストラバーサルリスク）
grep -rn --include='*.go' 'http\.ServeFile' . | grep -v vendor

# filepath.Clean によるサニタイズ確認
grep -rn --include='*.go' 'filepath\.Clean' . | grep -v vendor

# パスプレフィックスの検証
grep -rn --include='*.go' 'strings\.HasPrefix' . | grep -v vendor | grep -i path
```

## Race Conditions

### リスク

goroutine 間で共有変数への同時アクセスはデータ競合を引き起こす。`-race` フラグによるテストで検出可能。

### 検査パターン

```bash
# goroutine の使用箇所
grep -rn --include='*.go' 'go func\(' . | grep -v vendor

# グローバル変数の変更（競合リスク）
grep -rn --include='*.go' -E '^var\s+\w+\s+(map|slice|\[\])' . | grep -v vendor

# sync パッケージの使用（適切な保護の確認）
grep -rn --include='*.go' -E '(sync\.(Mutex|RWMutex|Map|WaitGroup|Once))' . | grep -v vendor

# atomic パッケージの使用
grep -rn --include='*.go' 'atomic\.' . | grep -v vendor

# channel の使用
grep -rn --include='*.go' -E 'make\(chan\s' . | grep -v vendor

# race detector でテスト実行
# go test -race ./...
```

## Memory Safety (unsafe)

### リスク

`unsafe` パッケージはメモリ安全性を完全にバイパスする。バッファオーバーフロー、型安全性の破壊が可能。

### 検査パターン

```bash
# unsafe パッケージの使用
grep -rn --include='*.go' '"unsafe"' . | grep -v vendor
grep -rn --include='*.go' 'unsafe\.Pointer' . | grep -v vendor

# reflect パッケージによる型操作
grep -rn --include='*.go' 'reflect\.Value' . | grep -v vendor | grep -i 'unsafe\|pointer'

# cgo の使用
grep -rn --include='*.go' -E '(import "C"|/\*.*#include)' . | grep -v vendor

# //go:linkname による非公開関数アクセス
grep -rn --include='*.go' '//go:linkname' . | grep -v vendor

# //go:nosplit / //go:noescape
grep -rn --include='*.go' -E '//go:(nosplit|noescape)' . | grep -v vendor
```

## Cryptography

### リスク

`math/rand` は暗号学的に安全でない。弱いハッシュアルゴリズム（MD5, SHA1）をパスワードや署名に使用するのは危険。

### 検査パターン

```bash
# math/rand の使用（暗号用途は危険）
grep -rn --include='*.go' '"math/rand"' . | grep -v vendor

# crypto/rand の使用（安全）
grep -rn --include='*.go' '"crypto/rand"' . | grep -v vendor

# 弱いハッシュ（MD5, SHA1）
grep -rn --include='*.go' -E '(md5\.(New|Sum)|sha1\.(New|Sum)|crypto\.MD5|crypto\.SHA1)' . | grep -v vendor

# 固定の暗号鍵
grep -rn --include='*.go' -E '([]byte\("|key\s*:?=\s*\[\]byte)' . | grep -v vendor | grep -v test

# AES の ECB モード（危険）
grep -rn --include='*.go' 'cipher\.NewECB' . | grep -v vendor

# 適切な暗号ライブラリの使用
grep -rn --include='*.go' -E '(golang\.org/x/crypto|crypto/aes|crypto/tls)' . | grep -v vendor
```

## HTTP Security

### 検査パターン

```bash
# CORS 設定
grep -rn --include='*.go' -E '(Access-Control-Allow-Origin|cors\.)' . | grep -v vendor

# ワイルドカード CORS（危険）
grep -rn --include='*.go' -E "Allow-Origin.*\*|AllowAllOrigins.*true" . | grep -v vendor

# HTTP タイムアウト設定の確認
grep -rn --include='*.go' -E '(ReadTimeout|WriteTimeout|IdleTimeout|ReadHeaderTimeout)' . | grep -v vendor

# タイムアウトなしの http.ListenAndServe（Slowloris 攻撃のリスク）
grep -rn --include='*.go' 'http\.ListenAndServe\(' . | grep -v vendor

# TLS 設定
grep -rn --include='*.go' -E '(tls\.Config|MinVersion|CipherSuites)' . | grep -v vendor

# セキュリティヘッダーの設定
grep -rn --include='*.go' -E '(X-Frame-Options|X-Content-Type|Strict-Transport|Content-Security-Policy)' . | grep -v vendor

# Cookie の Secure / HttpOnly フラグ
grep -rn --include='*.go' -E '(http\.Cookie|Secure:|HttpOnly:)' . | grep -v vendor
```

## Input Validation

### 検査パターン

```bash
# 整数オーバーフローリスク（strconv のエラーハンドリング）
grep -rn --include='*.go' -E 'strconv\.(Atoi|ParseInt|ParseUint)' . | grep -v vendor
# → エラーチェックがあるか確認

# ユーザー入力の直接使用
grep -rn --include='*.go' -E 'r\.(FormValue|URL\.Query|PostFormValue|PathValue)\(' . | grep -v vendor

# バリデーションライブラリの使用
grep -rn --include='*.go' -E '(validator\.Validate|validate:"required)' . | grep -v vendor

# JSON デコードのエラーハンドリング
grep -rn --include='*.go' 'json\.Decode\|json\.Unmarshal' . | grep -v vendor
```

## Error Handling

### リスク

Go のエラーハンドリングでエラーを無視すると、セキュリティバグが潜む。また `panic` は DoS につながる。

### 検査パターン

```bash
# エラーの無視（_ に代入）
grep -rn --include='*.go' -E '(,\s*_\s*:?=|_\s*=.*err)' . | grep -v vendor | grep -v test

# panic の使用（本番コードでは避けるべき）
grep -rn --include='*.go' 'panic\(' . | grep -v vendor | grep -v test

# recover の使用確認
grep -rn --include='*.go' 'recover\(\)' . | grep -v vendor

# log.Fatal（defer が実行されない）
grep -rn --include='*.go' 'log\.Fatal' . | grep -v vendor

# エラーメッセージに機密情報が含まれる可能性
grep -rn --include='*.go' -E '(fmt\.Errorf|errors\.New).*password\|secret\|token\|key' . | grep -v vendor
```

## Template Injection

### リスク

`text/template` は HTML エスケープを行わない。Web 出力には必ず `html/template` を使用する。

### 検査パターン

```bash
# text/template の使用（Web 出力では XSS リスク）
grep -rn --include='*.go' '"text/template"' . | grep -v vendor

# html/template の使用（安全）
grep -rn --include='*.go' '"html/template"' . | grep -v vendor

# template.HTML() による明示的エスケープ無効化
grep -rn --include='*.go' 'template\.HTML\(' . | grep -v vendor

# template.JS / template.URL の使用
grep -rn --include='*.go' -E 'template\.(JS|URL|CSS)\(' . | grep -v vendor
```

## TLS Configuration

### 検査パターン

```bash
# TLS の最小バージョン
grep -rn --include='*.go' 'MinVersion' . | grep -v vendor

# 非推奨の TLS バージョン（TLS 1.0, 1.1）
grep -rn --include='*.go' -E '(VersionTLS10|VersionTLS11|VersionSSL)' . | grep -v vendor

# InsecureSkipVerify（証明書検証の無効化）
grep -rn --include='*.go' 'InsecureSkipVerify\s*:\s*true' . | grep -v vendor

# 弱い暗号スイート
grep -rn --include='*.go' -E '(TLS_RSA_|TLS_ECDHE.*RC4|TLS_ECDHE.*3DES)' . | grep -v vendor
```

## Dependency Security

### 検査パターン

```bash
# go.sum の存在確認
ls -la go.sum 2>/dev/null || echo "go.sum not found"

# govulncheck による脆弱性チェック
govulncheck ./... 2>/dev/null || echo "govulncheck not installed"

# go.mod の依存バージョン確認
cat go.mod 2>/dev/null | grep -E '^\t'

# replace ディレクティブ（ローカルパッチの確認）
grep 'replace' go.mod 2>/dev/null

# 古い依存の確認
go list -m -u all 2>/dev/null | grep '\[' | head -20
```

## Go セキュリティチェックリスト

- [ ] SQL クエリがプレースホルダ（`$1`, `?`）を使用している
- [ ] `os/exec` にユーザー入力が直接渡されていない
- [ ] `filepath.Join` の結果が許可ディレクトリ内であることを検証している
- [ ] goroutine 間の共有変数が `sync.Mutex` / `sync.RWMutex` で保護されている
- [ ] `unsafe` パッケージの使用が最小限で、レビュー済み
- [ ] `crypto/rand` が暗号用途で使用されている（`math/rand` ではない）
- [ ] HTTP サーバーにタイムアウトが設定されている
- [ ] CORS がワイルドカードオリジンを許可していない
- [ ] `text/template` が Web 出力に使用されていない
- [ ] TLS 1.2 以上が設定されている
- [ ] `InsecureSkipVerify` が本番コードで `true` になっていない
- [ ] `panic` が本番コードの通常フローで使用されていない
- [ ] エラーが適切にハンドリングされ、無視されていない
- [ ] `govulncheck` で既知脆弱性がゼロ
- [ ] `go.sum` がリポジトリにコミットされている
- [ ] `-race` フラグでテストが通過している
