# Next.js Security Testing Reference

Next.js 固有の脆弱性パターンと検査ガイド。

## Server Components / Client Components データ漏洩

### リスク

Server Component から Client Component (`"use client"`) に渡される props は RSC プロトコルでシリアライズされ、ブラウザに送信される。データベースの生レコードや機密フィールドが露出する。

### 検査パターン

```bash
# Client Component の一覧
grep -rn '"use client"' --include='*.tsx' --include='*.ts' .

# Server Component から Client Component への props を確認
# → 上記ファイルの props に token, secret, password, apiKey が含まれていないか

# server-only パッケージの使用確認
grep -rn "import 'server-only'" --include='*.ts' --include='*.tsx' .

# process.env の Client Component 内使用（危険）
grep -rn 'process\.env' --include='*.tsx' . | \
  xargs -I{} sh -c 'grep -l "use client" "$(echo "{}" | cut -d: -f1)" 2>/dev/null'
```

## Server Actions セキュリティ

Server Actions は **認証・認可・入力検証なしの公開 POST エンドポイント**。

### 5 つの必須チェック

1. **認証チェック**: 全 Server Action で `auth()` / `getServerSession()` を呼んでいるか
2. **認可チェック**: リソースの所有者確認（IDOR 防止）
3. **入力検証**: Zod 等でランタイムバリデーション（TypeScript 型は消える）
4. **レート制限**: 機密操作に `@upstash/ratelimit` 等
5. **クロージャ漏洩**: `.bind()` の値はクライアントに露出

### 検査パターン

```bash
# Server Action ファイルの一覧
grep -rn '"use server"' --include='*.ts' --include='*.tsx' .

# Server Action 内で認証チェックがないファイル
for f in $(grep -rl '"use server"' --include='*.ts' --include='*.tsx' .); do
  if ! grep -qE '(auth\(\)|getServerSession|getCurrentUser|verifySession)' "$f"; then
    echo "NO AUTH: $f"
  fi
done

# 入力検証なしの Server Action
for f in $(grep -rl '"use server"' --include='*.ts' --include='*.tsx' .); do
  if ! grep -qE '(z\.|zod|schema\.(parse|safeParse)|validate|yup)' "$f"; then
    echo "NO VALIDATION: $f"
  fi
done

# .bind() の使用（値がクライアントに露出）
grep -rn '\.bind(null' --include='*.tsx' --include='*.ts' .
```

## Middleware セキュリティ

### CVE-2025-29927（CVSS 9.1）: Middleware バイパス

`x-middleware-subrequest` ヘッダーで全 Middleware をバイパス可能。

- 影響: Next.js <12.3.5, <13.5.9, <14.2.25, <15.2.3
- Vercel デプロイは自動保護済み。セルフホストは要パッチ

```bash
# Next.js バージョン確認
cat node_modules/next/package.json 2>/dev/null | grep '"version"'
# または
grep '"next"' package.json
```

### Middleware のパスマッチング

```bash
# middleware.ts/js の存在と matcher 設定
find . -name 'middleware.ts' -o -name 'middleware.js' | head -5
grep -n 'matcher' middleware.ts 2>/dev/null || grep -n 'matcher' middleware.js 2>/dev/null
```

**注意**: Middleware は**セキュリティ境界ではない**。Route Handler、Server Action、Data Access Layer でも認可チェックを実装すること。

## next.config セキュリティ設定

```bash
# next.config の全体確認
cat next.config.ts 2>/dev/null || cat next.config.js 2>/dev/null || cat next.config.mjs 2>/dev/null

# セキュリティヘッダーの設定確認
grep -A 20 'headers' next.config.* 2>/dev/null

# 画像最適化の remotePatterns（SSRF リスク）
grep -A 10 'remotePatterns' next.config.* 2>/dev/null

# ワイルドカードホスト名（SSRF）
grep -E 'hostname.*\*\*' next.config.* 2>/dev/null

# dangerouslyAllowSVG（XSS リスク）
grep 'dangerouslyAllowSVG' next.config.* 2>/dev/null

# ソースマップの本番公開
grep 'productionBrowserSourceMaps' next.config.* 2>/dev/null
```

## 環境変数の安全性

```bash
# NEXT_PUBLIC_ に含まれる機密情報
grep -rn 'NEXT_PUBLIC_' .env* 2>/dev/null | \
  grep -iE '(SECRET|SK_|PASSWORD|TOKEN|CREDENTIAL|PRIVATE)'

# .env ファイルの Git 追跡確認
git ls-files .env .env.local .env.production .env.development 2>/dev/null
```

| カテゴリ | 動作 | リスク |
|----------|------|--------|
| `NEXT_PUBLIC_*` | ビルド時にクライアント JS にインライン | 全ユーザーに公開 |
| サーバーのみの変数 | `process.env` でサーバーのみアクセス | 安全（Client Component に渡さなければ） |

## 入力検証・インジェクション

```bash
# SQL インジェクション（raw クエリ）
grep -rn --include='*.{ts,tsx}' \
  -E '(sql`.*\$\{|\.raw\(|Prisma\.\$queryRaw|\.execute\()' . | grep -v node_modules

# コマンドインジェクション
grep -rn --include='*.{ts,tsx}' \
  -E '(exec\(|execSync|spawn\(|child_process)' . | grep -v node_modules

# XSS パターン（DOM 直接操作）
grep -rn --include='*.{ts,tsx}' \
  -E '(innerHTML|outerHTML|document\.write)' . | grep -v node_modules

# オープンリダイレクト
grep -rn --include='*.{ts,tsx}' \
  -E '(redirect\(|router\.push\(|router\.replace\()' . | \
  grep -v node_modules
```

## 画像最適化 SSRF

`/_next/image?url=<target>` エンドポイントはサーバーサイドで画像を取得する。

```bash
# remotePatterns の過度な許可
grep -B2 -A10 'remotePatterns' next.config.* 2>/dev/null

# hostname: "**" は任意ドメインからの取得を許可（Critical）
```

**対策**: `remotePatterns` は厳密にホスト名・プロトコル・パスを指定する。

## 重要な CVE 一覧

| CVE | 深刻度 | 内容 | 修正バージョン |
|-----|--------|------|---------------|
| CVE-2025-55182 | Critical (10.0) | RSC デシリアライズ経由の RCE | Next.js 15.1.x+, React 19.0.1+ |
| CVE-2025-29927 | Critical (9.1) | Middleware 認可バイパス | 14.2.25, 15.2.3 |
| CVE-2025-49826 | High (7.5) | ISR キャッシュポイズニング DoS | 15.1.8+ |
| CVE-2024-34351 | High | Host ヘッダー SSRF | 14.1.1 |
| CVE-2024-46982 | High | Pages Router キャッシュポイズニング | 13.5.7, 14.2.10 |
| CVE-2026-27978 | Medium | Server Actions CSRF バイパス | 2026 パッチ |

## Next.js セキュリティチェックリスト

- [ ] Next.js バージョンが既知 CVE の修正版以上
- [ ] 全 Server Action に認証・認可・入力検証がある
- [ ] `NEXT_PUBLIC_` に秘密鍵が含まれていない
- [ ] セキュリティヘッダー（CSP, HSTS, X-Frame-Options 等）が設定されている
- [ ] `remotePatterns` がワイルドカードホスト名を使用していない
- [ ] `dangerouslyAllowSVG` が無効
- [ ] `productionBrowserSourceMaps` が無効
- [ ] Middleware が認可の唯一の防御線になっていない
- [ ] `.env` ファイルが Git 追跡されていない
- [ ] `server-only` パッケージがデータアクセス層で使用されている
