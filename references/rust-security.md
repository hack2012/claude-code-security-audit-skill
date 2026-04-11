# Rust Security Testing Reference

Rust 固有の脆弱性パターンと検査ガイド。unsafe ブロック、FFI 境界、Web フレームワーク対応。

## Unsafe Code

### リスク

`unsafe` ブロック内ではコンパイラのメモリ安全性保証がバイパスされる。use-after-free、バッファオーバーフロー、未定義動作が発生する可能性がある。

### 検査パターン

```bash
# unsafe ブロックの全箇所
grep -rn --include='*.rs' 'unsafe\s*{' . | grep -v target | grep -v vendor

# unsafe fn の定義
grep -rn --include='*.rs' 'unsafe\s*fn' . | grep -v target | grep -v vendor

# unsafe impl（Send / Sync の手動実装）
grep -rn --include='*.rs' 'unsafe\s*impl' . | grep -v target | grep -v vendor

# raw pointer の使用
grep -rn --include='*.rs' -E '(\*const\s|\*mut\s|as\s+\*const|as\s+\*mut)' . | grep -v target | grep -v vendor

# transmute（型の強制変換、非常に危険）
grep -rn --include='*.rs' 'transmute' . | grep -v target | grep -v vendor

# ptr::read / ptr::write
grep -rn --include='*.rs' -E '(ptr::(read|write|copy|swap|drop_in_place))' . | grep -v target | grep -v vendor

# SAFETY コメントの確認（unsafe の正当性説明）
grep -rn --include='*.rs' -B1 'unsafe' . | grep -i 'SAFETY' | grep -v target
```

## FFI Security

### リスク

`extern "C"` による C 言語との相互運用は、メモリ安全性を Rust の外に移す。NULL ポインタ、バッファオーバーフロー、メモリリークが発生しうる。

### 検査パターン

```bash
# extern "C" ブロック
grep -rn --include='*.rs' 'extern\s*"C"' . | grep -v target | grep -v vendor

# FFI 関数の呼び出し
grep -rn --include='*.rs' -E '(CString|CStr|c_char|c_int|c_void)' . | grep -v target | grep -v vendor

# libc クレートの使用
grep -rn --include='*.rs' 'libc::' . | grep -v target | grep -v vendor

# bindgen 生成コードの確認
grep -rn 'bindgen' Cargo.toml 2>/dev/null

# FFI 境界での NULL チェック
grep -rn --include='*.rs' -E '(is_null|NonNull|as_ref\(\))' . | grep -v target | grep -v vendor

# Box::from_raw（所有権の移転、二重解放リスク）
grep -rn --include='*.rs' 'Box::from_raw' . | grep -v target | grep -v vendor

# forget（メモリリーク）
grep -rn --include='*.rs' 'mem::forget\|std::mem::forget' . | grep -v target | grep -v vendor
```

## Memory Safety

### リスク

unsafe コード内での use-after-free、ダングリングポインタ、バッファオーバーフローは Rust のコンパイラでは検出されない。

### 検査パターン

```bash
# slice::from_raw_parts（バッファオーバーフローリスク）
grep -rn --include='*.rs' 'from_raw_parts' . | grep -v target | grep -v vendor

# ManuallyDrop（手動メモリ管理）
grep -rn --include='*.rs' 'ManuallyDrop' . | grep -v target | grep -v vendor

# MaybeUninit（未初期化メモリ）
grep -rn --include='*.rs' 'MaybeUninit' . | grep -v target | grep -v vendor

# Pin の使用（自己参照構造体の安全性）
grep -rn --include='*.rs' -E '(Pin<|pin_mut!|Unpin)' . | grep -v target | grep -v vendor

# alloc / dealloc の手動呼び出し
grep -rn --include='*.rs' -E '(alloc::(alloc|dealloc|realloc)|GlobalAlloc)' . | grep -v target | grep -v vendor

# offset / add / sub（ポインタ算術）
grep -rn --include='*.rs' -E '\.(offset|add|sub)\(' . | grep -v target | grep -v vendor | grep -i ptr
```

## Cryptography

### リスク

暗号処理の実装ミスは致命的なセキュリティホールになる。定数時間比較の欠如、弱いアルゴリズムの使用、不適切な乱数生成が主なリスク。

### 検査パターン

```bash
# 暗号ライブラリの使用確認
grep -rn -E '(ring|rustls|RustCrypto|aes|sha2|hmac|argon2|bcrypt|chacha20)' Cargo.toml 2>/dev/null

# rand クレートの使用（OsRng / ThreadRng の確認）
grep -rn --include='*.rs' -E '(OsRng|ThreadRng|StdRng|thread_rng|rand::)' . | grep -v target | grep -v vendor

# 固定シードの乱数生成（テスト以外では危険）
grep -rn --include='*.rs' 'SeedableRng\|seed_from_u64\|from_seed' . | grep -v target | grep -v vendor | grep -v test

# 定数時間比較（timing attack 対策）
grep -rn --include='*.rs' -E '(constant_time|ct_eq|subtle::)' . | grep -v target | grep -v vendor

# MD5 / SHA1 の使用（弱いハッシュ）
grep -rn --include='*.rs' -E '(md5|sha1|Md5|Sha1)[^a-zA-Z]' . | grep -v target | grep -v vendor

# ハードコードされた暗号鍵
grep -rn --include='*.rs' -E '(b"|&\[)[0-9a-fA-Fx, ]+\]' . | grep -v target | grep -v vendor | grep -i key
```

## Input Validation

### リスク

整数オーバーフロー（release ビルドではラップアラウンド）、`unwrap()` による panic、バリデーション不足が主なリスク。

### 検査パターン

```bash
# unwrap の使用（本番コードでは panic リスク）
grep -rn --include='*.rs' '\.unwrap()' . | grep -v target | grep -v vendor | grep -v test

# expect の使用（本番コードでの適切性を確認）
grep -rn --include='*.rs' '\.expect(' . | grep -v target | grep -v vendor | grep -v test

# 整数演算（オーバーフローリスク）
grep -rn --include='*.rs' -E '(checked_add|checked_sub|checked_mul|saturating_|overflowing_|wrapping_)' . | grep -v target | grep -v vendor

# as によるキャスト（精度損失、符号変換）
grep -rn --include='*.rs' -E '\bas\s+(u8|u16|u32|i8|i16|i32|usize|isize)\b' . | grep -v target | grep -v vendor

# 数値パース時のエラーハンドリング
grep -rn --include='*.rs' -E '\.parse::<(u|i|f)\w+>\(\)' . | grep -v target | grep -v vendor

# clippy の整数キャスト警告を有効化
grep -rn 'clippy::cast' . --include='*.rs' | grep -v target
```

## Error Handling

### リスク

`unwrap()` / `expect()` は panic を引き起こし、サービス停止（DoS）につながる。本番コードでは `Result` / `Option` の適切な処理が必須。

### 検査パターン

```bash
# unwrap の使用回数
grep -c --include='*.rs' -r '\.unwrap()' . 2>/dev/null | grep -v ':0$' | grep -v target | sort -t: -k2 -rn | head -10

# panic! マクロ
grep -rn --include='*.rs' 'panic!\(' . | grep -v target | grep -v vendor | grep -v test

# todo! / unimplemented!（本番コードに残存）
grep -rn --include='*.rs' -E '(todo!|unimplemented!)' . | grep -v target | grep -v vendor

# unreachable! の使用（到達可能な場合は UB）
grep -rn --include='*.rs' 'unreachable!' . | grep -v target | grep -v vendor

# エラーメッセージに機密情報
grep -rn --include='*.rs' -E '(eprintln!|tracing::(error|warn)).*password\|secret\|token\|key' . | grep -v target
```

## Web Frameworks (Actix-web / Axum / Rocket)

### 検査パターン

```bash
# フレームワークの特定
grep -E '(actix-web|axum|rocket|warp|tide)' Cargo.toml 2>/dev/null

# Actix-web: エクストラクタのバリデーション
grep -rn --include='*.rs' -E '(web::(Json|Query|Path|Form)|HttpRequest)' . | grep -v target | grep -v vendor

# Axum: エクストラクタの使用
grep -rn --include='*.rs' -E '(axum::extract|Extension|State<)' . | grep -v target | grep -v vendor

# CORS 設定
grep -rn --include='*.rs' -E '(Cors|cors|CorsLayer|AllowOrigin)' . | grep -v target | grep -v vendor

# ワイルドカード CORS（危険）
grep -rn --include='*.rs' -E '(permissive|any\(\)|allow_any_origin)' . | grep -v target | grep -v vendor

# 認証ミドルウェア
grep -rn --include='*.rs' -E '(middleware|guard|FromRequest|from_request)' . | grep -v target | grep -v vendor | grep -i auth

# レート制限
grep -rn --include='*.rs' -E '(rate_limit|throttle|governor|RateLimiter)' . | grep -v target | grep -v vendor

# セキュリティヘッダーの設定
grep -rn --include='*.rs' -E '(X-Frame-Options|Content-Security-Policy|Strict-Transport|helmet)' . | grep -v target
```

## SQL (sqlx / diesel)

### 検査パターン

```bash
# sqlx の使用確認
grep 'sqlx' Cargo.toml 2>/dev/null

# diesel の使用確認
grep 'diesel' Cargo.toml 2>/dev/null

# sqlx のコンパイル時検証クエリ（安全）
grep -rn --include='*.rs' -E '(sqlx::query!|query_as!)' . | grep -v target | grep -v vendor

# sqlx の動的クエリ（SQL Injection リスク）
grep -rn --include='*.rs' -E '(sqlx::query\(|QueryBuilder)' . | grep -v target | grep -v vendor

# format! で SQL 構築（危険）
grep -rn --include='*.rs' 'format!.*SELECT\|format!.*INSERT\|format!.*UPDATE\|format!.*DELETE' . | grep -v target | grep -v vendor

# diesel の raw SQL
grep -rn --include='*.rs' -E '(sql_query|diesel::sql_query)' . | grep -v target | grep -v vendor
```

## Dependency Security

### 検査パターン

```bash
# cargo-audit による脆弱性チェック
cargo audit 2>/dev/null || echo "cargo-audit not installed"

# cargo-deny による包括的チェック
cargo deny check 2>/dev/null || echo "cargo-deny not installed"

# Cargo.lock の存在確認（バイナリプロジェクトでは必須）
ls -la Cargo.lock 2>/dev/null || echo "Cargo.lock not found"

# 依存関係の一覧
cargo tree --depth 1 2>/dev/null | head -30

# yanked クレートの確認
cargo audit --deny yanked 2>/dev/null

# 安全でないクレートの使用（cargo-geiger）
cargo geiger 2>/dev/null || echo "cargo-geiger not installed"
```

## Concurrency Safety

### リスク

unsafe コード内での `Send` / `Sync` の不正な実装はデータ競合を引き起こす。コンパイラの保護をバイパスしているため、検出が困難。

### 検査パターン

```bash
# unsafe impl Send / Sync（手動実装は要レビュー）
grep -rn --include='*.rs' -E 'unsafe\s+impl\s+(Send|Sync)' . | grep -v target | grep -v vendor

# Arc / Mutex の使用パターン
grep -rn --include='*.rs' -E '(Arc<|Mutex<|RwLock<|AtomicBool|AtomicUsize)' . | grep -v target | grep -v vendor

# crossbeam の使用
grep -rn --include='*.rs' 'crossbeam' . | grep -v target | grep -v vendor

# tokio::spawn での shared state
grep -rn --include='*.rs' 'tokio::spawn' . | grep -v target | grep -v vendor

# static mut（データ競合リスク、非推奨）
grep -rn --include='*.rs' 'static\s*mut' . | grep -v target | grep -v vendor
```

## Serialization (serde)

### リスク

信頼できないソースからのデシリアライズは、メモリ枯渇（巨大な配列）やロジックバグを引き起こす可能性がある。

### 検査パターン

```bash
# serde の使用確認
grep 'serde' Cargo.toml 2>/dev/null

# Deserialize の導出
grep -rn --include='*.rs' 'Deserialize' . | grep -v target | grep -v vendor

# カスタム Deserialize の実装（ロジックバグリスク）
grep -rn --include='*.rs' "impl.*Deserialize.*for" . | grep -v target | grep -v vendor

# serde_json::from_str / from_slice（入力サイズ制限の確認）
grep -rn --include='*.rs' -E '(from_str|from_slice|from_reader)\(' . | grep -v target | grep -v vendor | grep -i serde

# #[serde(deny_unknown_fields)]（未知フィールドの拒否）
grep -rn --include='*.rs' 'deny_unknown_fields' . | grep -v target | grep -v vendor

# bincode / postcard 等のバイナリフォーマット
grep -rn -E '(bincode|postcard|ciborium|rmp-serde)' Cargo.toml 2>/dev/null
```

## File System

### リスク

パストラバーサル（`../` によるディレクトリ脱出）と TOCTOU（Time-of-check-to-time-of-use）が主なリスク。

### 検査パターン

```bash
# ファイルパスにユーザー入力を使用
grep -rn --include='*.rs' -E '(Path::new|PathBuf::from)\(' . | grep -v target | grep -v vendor

# ファイル操作
grep -rn --include='*.rs' -E '(fs::(read|write|remove|create_dir|rename|copy)|File::(open|create))' . | grep -v target | grep -v vendor

# canonicalize によるパス正規化（TOCTOU リスクあり）
grep -rn --include='*.rs' 'canonicalize' . | grep -v target | grep -v vendor

# tempfile の使用（安全な一時ファイル）
grep -rn --include='*.rs' 'tempfile' . | grep -v target | grep -v vendor

# パスプレフィックスの検証
grep -rn --include='*.rs' 'starts_with\|strip_prefix' . | grep -v target | grep -v vendor | grep -i path

# シンボリックリンクの追跡
grep -rn --include='*.rs' -E '(symlink_metadata|read_link|follow_links)' . | grep -v target | grep -v vendor
```

## unsafe コードの分類

| パターン | リスクレベル | 説明 |
|----------|-------------|------|
| `unsafe { }` ブロック | Medium-High | コンパイラ保護のバイパス |
| `unsafe fn` | High | 呼び出し側に安全性責任を移転 |
| `unsafe impl Send/Sync` | Critical | 並行性の安全性を手動保証 |
| `transmute` | Critical | 任意の型変換、UB のリスク |
| `from_raw_parts` | High | バッファオーバーフローのリスク |
| `static mut` | Critical | データ競合、非推奨 |
| `extern "C"` | High | FFI 境界、メモリ安全性の断絶 |

## Rust セキュリティチェックリスト

- [ ] `unsafe` ブロックが最小限で、各箇所に SAFETY コメントがある
- [ ] `transmute` の使用が正当化されている
- [ ] FFI 境界で NULL チェックとバッファサイズ検証がある
- [ ] `unsafe impl Send/Sync` がデータ競合を起こさないことが証明されている
- [ ] `static mut` が使用されていない（代替: `OnceLock`, `Atomic*`, `Mutex`）
- [ ] 暗号処理に `ring` / `RustCrypto` 等の実績あるクレートを使用している
- [ ] 固定シードの乱数生成がテスト以外で使用されていない
- [ ] `unwrap()` / `expect()` が本番コードで適切にハンドリングされている
- [ ] `todo!` / `unimplemented!` が本番コードに残存していない
- [ ] SQL クエリが `sqlx::query!` マクロまたはパラメータ化されている
- [ ] CORS がワイルドカードオリジンを許可していない
- [ ] Web エンドポイントに認証ミドルウェアが設定されている
- [ ] `cargo audit` で既知脆弱性がゼロ
- [ ] `Cargo.lock` がリポジトリにコミットされている
- [ ] 整数演算に `checked_*` / `saturating_*` メソッドを使用している
- [ ] パストラバーサル対策（プレフィックス検証）が実装されている
- [ ] serde デシリアライズに入力サイズの制限がある
