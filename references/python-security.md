# Python Security Testing Reference

Python (Django / FastAPI / Flask) 固有の脆弱性パターンと検査ガイド。OWASP Top 10 + Bandit ルールに基づく。

## SQL Injection

### リスク

ORM を使用していても、raw クエリや文字列フォーマットによる SQL 構築で SQL Injection が発生する。Django の `extra()`, `raw()`, FastAPI/Flask での直接 SQL 実行が主なリスク。

### 検査パターン

```bash
# Django raw SQL（B610）
grep -rn --include='*.py' -E '\.raw\(|\.extra\(' . | grep -v venv

# 文字列フォーマットによる SQL 構築（B608）
grep -rn --include='*.py' \
  -E "(execute\(.*(%s|%d|\.format\(|f['\"])|cursor\.execute\(.*\+)" . | grep -v venv

# SQLAlchemy text() 内の文字列結合
grep -rn --include='*.py' -E 'text\(.*(\+|\.format|f["\x27])' . | grep -v venv

# Django filter での安全でないクエリ構築
grep -rn --include='*.py' -E '__in=.*\[.*request\.' . | grep -v venv

# ORM の where 句に直接文字列を渡すパターン
grep -rn --include='*.py' -E '\.filter\(.*%.*request\.' . | grep -v venv
```

## Command Injection

### リスク

`os.system()`, `subprocess` を shell=True で使用、`eval()`, `exec()` によるコード実行は任意コマンド実行につながる。Bandit B101, B301, B602, B603 に対応。

### 検査パターン

```bash
# os.system / os.popen（B605, B606）
grep -rn --include='*.py' -E '(os\.system|os\.popen)\(' . | grep -v venv

# subprocess with shell=True（B602）
grep -rn --include='*.py' -E 'subprocess\.\w+\(.*shell\s*=\s*True' . | grep -v venv

# eval / exec（B307）
grep -rn --include='*.py' -E '\b(eval|exec)\(' . | grep -v venv

# compile + exec パターン
grep -rn --include='*.py' -E 'compile\(.*exec\(' . | grep -v venv

# __import__ による動的インポート
grep -rn --include='*.py' '__import__\(' . | grep -v venv
```

## Server-Side Template Injection (SSTI)

### リスク

Jinja2 テンプレートや Django テンプレートにユーザー入力が直接渡されると、サーバー側でコードが実行される。

### 検査パターン

```bash
# Jinja2 で autoescape 無効（B701）
grep -rn --include='*.py' -E 'Environment\(.*autoescape\s*=\s*False' . | grep -v venv

# Template を文字列から直接生成
grep -rn --include='*.py' -E '(Template\(.*request\.|render_template_string\()' . | grep -v venv

# Django mark_safe（XSS リスク）
grep -rn --include='*.py' 'mark_safe\(' . | grep -v venv

# Django の |safe フィルター
grep -rn --include='*.html' '|safe' . | grep -v venv
```

## Authentication

### 検査パターン

```bash
# Django: 認証デコレータの欠如を確認
grep -rn --include='*.py' -E 'def (post|put|patch|delete)\(' . | grep -v venv
# → 対応する @login_required / @permission_required があるか確認

# Django REST Framework: 認証クラスの設定
grep -rn --include='*.py' -E '(authentication_classes|permission_classes)\s*=' . | grep -v venv
grep -rn --include='*.py' 'AllowAny' . | grep -v venv

# FastAPI: Depends() による認証確認
grep -rn --include='*.py' -E '@(app|router)\.(get|post|put|delete|patch)' . | grep -v venv
# → Depends(get_current_user) 等があるか確認

# Flask-Login: login_required の使用
grep -rn --include='*.py' '@login_required' . | grep -v venv

# パスワードのハッシュ化確認
grep -rn --include='*.py' -E '(make_password|check_password|pbkdf2|bcrypt|argon2)' . | grep -v venv

# 平文パスワードの保存（危険）
grep -rn --include='*.py' -E 'password\s*=' . | grep -v venv | grep -v hash | grep -v bcrypt
```

## CSRF Protection

### 検査パターン

```bash
# Django: CSRF middleware の確認
grep -rn --include='*.py' 'CsrfViewMiddleware' . | grep -v venv

# Django: csrf_exempt の使用（要確認）
grep -rn --include='*.py' '@csrf_exempt' . | grep -v venv

# FastAPI: CORS 設定
grep -rn --include='*.py' -E '(CORSMiddleware|allow_origins)' . | grep -v venv

# FastAPI: CORS でワイルドカードオリジン（危険）
grep -rn --include='*.py' -E "allow_origins\s*=\s*\[.*['\"]?\*['\"]?" . | grep -v venv

# Flask-WTF: CSRF 保護の確認
grep -rn --include='*.py' -E '(CSRFProtect|csrf\.init_app)' . | grep -v venv
```

## Deserialization

### リスク

`pickle`, `yaml.load()`, `marshal` によるデシリアライズはリモートコード実行を引き起こす。Bandit B301, B506 に対応。

### 検査パターン

```bash
# pickle の使用（B301）
grep -rn --include='*.py' -E '(pickle\.loads?|cPickle\.loads?|shelve\.open)\(' . | grep -v venv

# yaml.load without SafeLoader（B506）
grep -rn --include='*.py' 'yaml\.load\(' . | grep -v venv | grep -v SafeLoader | grep -v safe_load

# marshal の使用（B302）
grep -rn --include='*.py' 'marshal\.loads?\(' . | grep -v venv

# jsonpickle（危険なライブラリ）
grep -rn --include='*.py' 'jsonpickle' . | grep -v venv
```

## File Upload

### 検査パターン

```bash
# ファイル拡張子の検証なし
grep -rn --include='*.py' -E '(request\.files|UploadFile|FileField)' . | grep -v venv
# → allowed_extensions / content_type チェックがあるか確認

# パストラバーサル: ユーザー入力をファイル名に使用
grep -rn --include='*.py' -E '(os\.path\.join|Path)\(.*request\.' . | grep -v venv

# Django FileField の upload_to 設定
grep -rn --include='*.py' 'upload_to=' . | grep -v venv

# ファイルサイズ制限の確認
grep -rn --include='*.py' -E '(MAX_UPLOAD_SIZE|FILE_UPLOAD_MAX|content_length)' . | grep -v venv
```

## Secret Management

### 検査パターン

```bash
# ハードコードされた秘密鍵（B105, B106, B107）
grep -rn --include='*.py' \
  -E "(SECRET_KEY|API_KEY|PASSWORD|TOKEN)\s*=\s*['\"]" . | grep -v venv | grep -v test

# .env ファイルの Git 追跡
git ls-files .env .env.local .env.production 2>/dev/null

# .env に含まれる秘密情報
grep -iE '(SECRET|PASSWORD|TOKEN|API_KEY|PRIVATE)' .env* 2>/dev/null

# settings.py での DEBUG 設定
grep -rn --include='*.py' 'DEBUG\s*=\s*True' . | grep -v venv | grep -v test

# python-dotenv の使用確認
grep -rn --include='*.py' 'load_dotenv' . | grep -v venv
```

## Django 固有のセキュリティ設定

### 検査パターン

```bash
# DEBUG モード（本番で True は Critical）
grep -rn 'DEBUG\s*=\s*True' --include='settings.py' . | grep -v venv

# ALLOWED_HOSTS が空またはワイルドカード
grep -rn 'ALLOWED_HOSTS' --include='settings.py' . | grep -v venv

# SECRET_KEY のハードコード
grep -rn 'SECRET_KEY\s*=' --include='settings.py' . | grep -v venv

# セキュリティ関連の設定確認
grep -rn --include='settings.py' \
  -E '(SECURE_SSL_REDIRECT|SECURE_HSTS|SESSION_COOKIE_SECURE|CSRF_COOKIE_SECURE|SECURE_BROWSER_XSS_FILTER|X_FRAME_OPTIONS)' . | grep -v venv

# セキュリティ Middleware の順序
grep -A 20 'MIDDLEWARE' --include='settings.py' -rn . | grep -v venv
```

| 設定項目 | 推奨値 | リスク |
|----------|--------|--------|
| `DEBUG` | `False` | デバッグ情報の露出、フルトレースバック |
| `ALLOWED_HOSTS` | 具体的なドメイン | Host ヘッダー攻撃 |
| `SECRET_KEY` | 環境変数から取得 | セッション偽造、CSRF バイパス |
| `SECURE_SSL_REDIRECT` | `True` | HTTP での通信傍受 |
| `SESSION_COOKIE_SECURE` | `True` | Cookie の平文送信 |
| `CSRF_COOKIE_SECURE` | `True` | CSRF トークンの平文送信 |
| `SECURE_HSTS_SECONDS` | `31536000` | HTTPS ダウングレード |

## FastAPI 固有のセキュリティ

### 検査パターン

```bash
# 認証なしのエンドポイント
grep -rn --include='*.py' -E '@(app|router)\.(get|post|put|delete)' . | grep -v venv
# → Depends() による認証チェックがあるか確認

# Pydantic モデルのバリデーション
grep -rn --include='*.py' -E 'class \w+\(BaseModel\)' . | grep -v venv

# レスポンスモデルの指定（データ漏洩防止）
grep -rn --include='*.py' 'response_model=' . | grep -v venv

# CORS の設定
grep -rn --include='*.py' -A5 'CORSMiddleware' . | grep -v venv
```

## Flask 固有のセキュリティ

### 検査パターン

```bash
# Flask debug モード（本番で True は Critical）
grep -rn --include='*.py' -E '(app\.run\(.*debug\s*=\s*True|app\.debug\s*=\s*True)' . | grep -v venv

# Flask SECRET_KEY の設定
grep -rn --include='*.py' "app.secret_key\s*=\s*['\"]" . | grep -v venv

# Flask セッション設定
grep -rn --include='*.py' -E '(SESSION_COOKIE_SECURE|SESSION_COOKIE_HTTPONLY|PERMANENT_SESSION_LIFETIME)' . | grep -v venv

# Flask-Talisman（セキュリティヘッダー）の使用
grep -rn --include='*.py' 'Talisman' . | grep -v venv
```

## Dependency Security

### 検査パターン

```bash
# 既知の脆弱性チェック
pip-audit 2>/dev/null || echo "pip-audit not installed"
safety check --file requirements.txt 2>/dev/null || echo "safety not installed"

# Bandit による静的解析
bandit -r . -ll 2>/dev/null || echo "bandit not installed"

# requirements.txt でバージョン固定されていない依存
grep -E '^[a-zA-Z]' requirements.txt 2>/dev/null | grep -v '=='

# setup.py / pyproject.toml の依存確認
grep -A 50 'install_requires' setup.py 2>/dev/null
grep -A 50 '\[project\]' pyproject.toml 2>/dev/null | grep -A 30 'dependencies'
```

## Bandit ルールマッピング

| Bandit ID | 内容 | 深刻度 |
|-----------|------|--------|
| B101 | assert の使用（本番では無効化される） | Low |
| B105-B107 | ハードコードされたパスワード / 秘密鍵 | Medium |
| B301 | pickle の使用 | High |
| B302 | marshal の使用 | High |
| B307 | eval() の使用 | High |
| B501 | SSL 証明書検証の無効化 | High |
| B506 | yaml.load() の安全でない使用 | High |
| B602 | subprocess with shell=True | High |
| B605 | os.system() の使用 | High |
| B608 | SQL Injection（文字列フォーマット） | Medium |
| B610 | Django extra() の使用 | Medium |
| B701 | Jinja2 autoescape 無効 | High |

## Python セキュリティチェックリスト

- [ ] SQL クエリがパラメータ化されている（文字列フォーマット不使用）
- [ ] `eval()`, `exec()`, `os.system()` が使用されていない
- [ ] `pickle.load()`, `yaml.load()` が安全なローダーを使用している
- [ ] Django の `DEBUG = False` が本番設定で確認済み
- [ ] `ALLOWED_HOSTS` が適切に設定されている
- [ ] `SECRET_KEY` がハードコードされていない
- [ ] 全エンドポイントに認証・認可チェックがある
- [ ] CSRF 保護が有効（`@csrf_exempt` の使用が最小限）
- [ ] ファイルアップロードに拡張子・サイズ制限がある
- [ ] `.env` ファイルが Git 追跡されていない
- [ ] `pip-audit` / `safety` で既知脆弱性がゼロ
- [ ] Bandit の High 以上の警告がゼロ
- [ ] セキュリティヘッダー（CSP, HSTS 等）が設定されている
- [ ] FastAPI の CORS 設定でワイルドカードオリジンが使用されていない
- [ ] Flask の debug モードが本番で無効
- [ ] Jinja2 で autoescape が有効
