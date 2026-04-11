# Flutter Security Testing Reference

Flutter/Dart アプリケーション向けセキュリティ検査ガイド。OWASP MASVS v2 に基づくクロスプラットフォーム固有のリスクを網羅。

## データ保存

### 検査対象

- **SharedPreferences**: 機密データの平文保存（`shared_preferences` パッケージ）
- **flutter_secure_storage**: Keychain / KeyStore を利用した暗号化保存の推奨
- **sqflite**: SQLite データベースの暗号化有無
- **Hive / Isar**: ローカル DB への機密データ保存
- **ファイル保存**: `path_provider` による一時/永続ファイルの保護
- **ログ出力**: `print` / `debugPrint` / `log` での機密データ出力
- **クリップボード**: `Clipboard.setData` による機密データコピー

```bash
# SharedPreferences への機密データ保存
grep -rn --include='*.dart' \
  -E '(SharedPreferences|\.setString|\.setInt|\.setBool)' . | \
  grep -iE '(password|token|secret|key|credential|session|auth|pin)'

# flutter_secure_storage の使用確認（推奨パターン）
grep -rn --include='*.dart' \
  -E '(FlutterSecureStorage|secureStorage|\.write\(key:|\.read\(key:)' .

# sqflite の使用と暗号化確認
grep -rn --include='*.dart' \
  -E '(openDatabase|getDatabasesPath|sqflite|sqflite_sqlcipher)' .

# pubspec.yaml での sqflite / sqlcipher 依存
grep -n -E '(sqflite|sqflite_sqlcipher|flutter_secure_storage|hive|isar)' pubspec.yaml

# ログ出力の機密データ
grep -rn --include='*.dart' \
  -E '(print\(|debugPrint\(|log\(|logger\.)' . | \
  grep -iE '(password|token|secret|key|credential|bearer|session)'

# ファイル保存
grep -rn --include='*.dart' \
  -E '(File\(|writeAsString|writeAsBytes|getTemporaryDirectory|getApplicationDocumentsDirectory)' .

# クリップボードへのコピー
grep -rn --include='*.dart' \
  -E '(Clipboard\.setData|ClipboardData)' .
```

## 暗号

### 検査対象

- **弱いアルゴリズム**: MD5, SHA1（署名用途）, DES, RC4
- **pointycastle / encrypt**: 暗号パッケージの適切な使用
- **ハードコードされた鍵**: Dart コード内の暗号鍵・IV・ソルト
- **乱数生成**: `Random()` の暗号用途使用（`Random.secure()` を推奨）
- **鍵管理**: 鍵の安全な生成と保管

```bash
# 弱い暗号アルゴリズム
grep -rn --include='*.dart' \
  -iE '(md5|sha1|MD5|SHA1|DES|RC4|\.convert\(.*md5|\.convert\(.*sha1)' .

# ハードコードされた暗号鍵
grep -rn --include='*.dart' \
  -E "(const|final|var)\s+(key|secret|iv|nonce|salt|aesKey|encryptionKey)\s*=\s*['\"][^'\"]{8,}['\"]" .

# 暗号パッケージの使用
grep -rn --include='*.dart' \
  -E '(import.*pointycastle|import.*encrypt|import.*crypto|AES|RSA|Encrypter|IV\.fromLength)' .

# 安全でない乱数生成
grep -rn --include='*.dart' \
  -E 'Random\(\)' . | grep -v 'Random\.secure'

# pubspec.yaml での暗号関連依存
grep -n -E '(pointycastle|encrypt|crypto|cryptography)' pubspec.yaml
```

## ネットワーク

### 検査対象

- **http / dio パッケージ**: HTTPS の使用、Cleartext 通信の検出
- **Certificate Pinning**: `SecurityContext` や dio インターセプターによるピン留め
- **プロキシ検出**: 中間者攻撃への対策
- **API キーの露出**: リクエストヘッダー・URL パラメータ内のキー
- **badCertificateCallback**: 証明書検証の無効化

```bash
# HTTP（非 HTTPS）URL の使用
grep -rn --include='*.dart' \
  -E "http://[^l][^o][^c][^a][^l]" . | grep -v '// '

# dio / http パッケージの使用
grep -rn --include='*.dart' \
  -E '(import.*package:dio|import.*package:http/|Dio\(|http\.Client|HttpClient)' .

# 証明書検証の無効化（badCertificateCallback で true を返す = 危険）
grep -rn --include='*.dart' \
  -E '(badCertificateCallback|onBadCertificate)' .

# Certificate Pinning 実装
grep -rn --include='*.dart' \
  -E '(SecurityContext|setTrustedCertificates|clientCertificate|certificatePinning)' .

# API キーのヘッダー埋め込み
grep -rn --include='*.dart' \
  -E "(headers|Header).*['\"]?(Authorization|X-Api-Key|api[_-]?key)['\"]?" . | \
  grep -v 'TODO\|FIXME'

# プロキシ設定
grep -rn --include='*.dart' \
  -E '(findProxy|HttpClient\..*proxy|PROXY|badCertificateCallback.*true)' .

# Android Network Security Config の参照
find . -path '*/android/*' -name 'network_security_config.xml' \
  -exec cat {} \;

# iOS ATS 設定
find . -path '*/ios/*' -name 'Info.plist' -not -path '*/Pods/*' \
  -exec grep -A 5 'NSAppTransportSecurity' {} +
```

## Platform Channel セキュリティ

### 検査対象

- **MethodChannel**: ネイティブコードとの通信内容の検証
- **EventChannel**: ストリームデータの機密性
- **BasicMessageChannel**: メッセージの暗号化・検証
- **ネイティブコードインジェクション**: チャネル名のハードコード・偽装リスク
- **データシリアライゼーション**: チャネル経由のデータ型安全性

```bash
# MethodChannel の定義
grep -rn --include='*.dart' \
  -E '(MethodChannel|EventChannel|BasicMessageChannel)\s*\(' .

# チャネル名のハードコード
grep -rn --include='*.dart' \
  -E "(MethodChannel|EventChannel)\s*\(\s*['\"]" .

# ネイティブ側のチャネル実装（Kotlin）
grep -rn --include='*.kt' \
  -E '(MethodChannel|FlutterMethodChannel|setMethodCallHandler)' .

# ネイティブ側のチャネル実装（Swift）
grep -rn --include='*.swift' \
  -E '(FlutterMethodChannel|FlutterEventChannel|FlutterBasicMessageChannel)' .

# チャネル経由の機密データ
grep -rn --include='*.dart' \
  -E 'invokeMethod.*' . | \
  grep -iE '(password|token|secret|key|credential|auth)'
```

## コード保護

### 検査対象

- **難読化**: `--obfuscate` フラグと `--split-debug-info` の使用
- **デバッグモード検出**: `kDebugMode` / `kReleaseMode` / `kProfileMode` の使用
- **assert 文**: Release ビルドでの assert 動作確認
- **デバッグコードの残存**: `debugPrint`, `print`, `developer.log` の残存
- **ソースマップ**: デバッグ情報の本番公開リスク

```bash
# 難読化設定の確認（build コマンド）
find . -name 'Makefile' -o -name '*.sh' -o -name '*.yaml' -o -name '*.yml' | \
  xargs grep -l 'obfuscate\|split-debug-info' 2>/dev/null

# デバッグモード判定
grep -rn --include='*.dart' \
  -E '(kDebugMode|kReleaseMode|kProfileMode|Foundation\.kDebugMode)' .

# デバッグ専用コードのガード確認
grep -rn --include='*.dart' -B 1 \
  -E '(print\(|debugPrint\(|developer\.log\()' . | \
  grep -v 'kDebugMode\|assert\|// '

# assert 文の確認
grep -rn --include='*.dart' \
  -E '^\s*assert\(' .

# Dart DevTools / Observatory の設定
grep -rn --include='*.dart' \
  -E '(DevTools|Observatory|debugger\(\)|developer\.)' .
```

## WebView セキュリティ

### 検査対象

- **webview_flutter**: JavaScript の有効化設定
- **JavaScriptChannel**: ネイティブブリッジの入力検証
- **NavigationDelegate**: URL フィルタリングの実装
- **ローカルファイルアクセス**: file:// スキームの制御

```bash
# WebView の JavaScript 有効化
grep -rn --include='*.dart' \
  -E '(JavascriptMode\.unrestricted|javaScriptMode.*JavaScriptMode\.unrestricted|WebView\(|WebViewController|InAppWebView)' .

# JavaScriptChannel の定義
grep -rn --include='*.dart' \
  -E '(JavascriptChannel|JavaScriptChannel|addJavaScriptChannel|onMessageReceived)' .

# NavigationDelegate のフィルタリング
grep -rn --include='*.dart' \
  -E '(NavigationDelegate|navigationDelegate|onNavigationRequest|setNavigationDelegate)' .

# WebView でのローカルファイル読み込み
grep -rn --include='*.dart' \
  -E '(loadFile|loadFlutterAsset|file://|loadHtmlString)' .

# pubspec.yaml の WebView 依存
grep -n -E '(webview_flutter|flutter_inappwebview|flutter_webview_plugin)' pubspec.yaml
```

## State Management とメモリ

### 検査対象

- **機密データの State 保持**: Provider / Riverpod / BLoC での機密データ管理
- **メモリクリーンアップ**: dispose 時の機密データ消去
- **グローバル状態**: シングルトンやグローバル変数での機密データ保持
- **スクリーンショット保護**: バックグラウンド遷移時のデータ保護

```bash
# State 内の機密データ
grep -rn --include='*.dart' \
  -E '(StateNotifier|ChangeNotifier|BlocProvider|Cubit|Provider)' . | \
  grep -iE '(password|token|secret|credential|auth)'

# dispose メソッドの実装確認
grep -rn --include='*.dart' \
  -E '(void\s+dispose\(\)|@override.*dispose)' .

# グローバル変数での機密データ
grep -rn --include='*.dart' \
  -E '^(final|var|late)\s+\w*(token|secret|password|key|credential)' .

# WidgetsBindingObserver（ライフサイクル監視）
grep -rn --include='*.dart' \
  -E '(WidgetsBindingObserver|didChangeAppLifecycleState|AppLifecycleState)' .
```

## ビルドセキュリティ

### 検査対象

- **API キーの Dart コード埋め込み**: ソースコード内のシークレット
- **.env ファイル**: `flutter_dotenv` の使用と `.gitignore` 設定
- **--dart-define**: ビルド時の環境変数注入
- **アセットファイル**: `assets/` ディレクトリ内の機密ファイル
- **pubspec.yaml**: 不要な依存・古い依存の検出

```bash
# Dart コード内の API キー・シークレット
grep -rn --include='*.dart' \
  -E "(const|final)\s+\w*(apiKey|apiSecret|appKey|appSecret|clientSecret|secretKey)\s*=\s*['\"][^'\"]+['\"]" .

# .env ファイルの存在と .gitignore 確認
find . -name '.env' -o -name '.env.*' -o -name 'env.dart' | head -10
grep -n '\.env' .gitignore 2>/dev/null

# flutter_dotenv の使用
grep -rn --include='*.dart' \
  -E '(dotenv|DotEnv|flutter_dotenv|env\.get|env\[)' .

# --dart-define の使用確認
find . -name 'Makefile' -o -name '*.sh' -o -name '*.yaml' | \
  xargs grep -l 'dart-define\|dart-define-from-file' 2>/dev/null

# アセットディレクトリの機密ファイル
find . -path '*/assets/*' \
  -iname '*.pem' -o -iname '*.key' -o -iname '*.p12' -o -iname '*.json' | \
  grep -iE '(key|secret|credential|service.account|google.services)'

# 古い依存の検出
grep -rn --include='pubspec.yaml' \
  -E '^\s+\w+:\s*\^?\d' . | head -20

# Android の google-services.json
find . -path '*/android/*' -name 'google-services.json' | head -5

# iOS の GoogleService-Info.plist
find . -path '*/ios/*' -name 'GoogleService-Info.plist' | head -5
```

## Flutter 検査チェックリスト

- [ ] SharedPreferences に機密データが平文で保存されていない（`flutter_secure_storage` を使用）
- [ ] sqflite で暗号化が有効化されている（`sqflite_sqlcipher` の使用）
- [ ] ログに機密データが出力されていない（Release ビルドで `print` 無効化）
- [ ] HTTPS のみ使用され、HTTP 通信が存在しない
- [ ] `badCertificateCallback` が本番で証明書検証を無効化していない
- [ ] Certificate Pinning が実装されている
- [ ] API キーが Dart コード内にハードコードされていない（`--dart-define` を使用）
- [ ] `.env` ファイルが `.gitignore` に含まれている
- [ ] `--obfuscate` と `--split-debug-info` が Release ビルドで使用されている
- [ ] `kDebugMode` でデバッグコードが適切にガードされている
- [ ] WebView で `JavascriptMode.unrestricted` が必要最小限に使用されている
- [ ] JavaScriptChannel の入力が検証・サニタイズされている
- [ ] Platform Channel 経由のデータが検証されている
- [ ] State / Provider 内の機密データが dispose 時に消去されている
- [ ] `Random.secure()` が暗号用途に使用されている
- [ ] 弱い暗号アルゴリズム（MD5, SHA1, DES）が使用されていない
- [ ] Android の `network_security_config.xml` で cleartext が禁止されている
- [ ] iOS の ATS（App Transport Security）が有効化されている
- [ ] `google-services.json` / `GoogleService-Info.plist` が適切に管理されている
- [ ] 不要なパーミッションが `AndroidManifest.xml` / `Info.plist` から除去されている
