# Android Security Testing Reference

OWASP MASVS v2 / MASTG に基づく Kotlin/Java 向け詳細検査ガイド。

## MASVS-STORAGE: データ保存

### 検査対象

- **SharedPreferences**: 機密データ（トークン、パスワード、個人情報）の平文保存禁止
- **EncryptedSharedPreferences**: 暗号化された SharedPreferences の使用推奨
- **SQLite**: 暗号化の有無（SQLCipher の使用）、WAL ファイルの保護
- **Internal Storage**: `MODE_WORLD_READABLE` / `MODE_WORLD_WRITABLE` の使用禁止
- **External Storage**: SD カード等の外部ストレージへの機密データ書き込み禁止
- **ログ出力**: `Log.d` / `Log.v` / `Log.i` での機密データ出力
- **クリップボード**: `ClipboardManager` への機密データコピー
- **バックアップ**: `android:allowBackup="true"` によるデータ漏洩リスク

```bash
# SharedPreferences への機密データ保存
grep -rn --include='*.kt' --include='*.java' \
  -E '(getSharedPreferences|PreferenceManager\.getDefaultSharedPreferences)' . | \
  grep -iE '(password|token|secret|key|credential|session|auth|pin)'

# EncryptedSharedPreferences の使用確認（推奨パターン）
grep -rn --include='*.kt' --include='*.java' \
  -E 'EncryptedSharedPreferences' .

# SharedPreferences の MODE 確認（WORLD_READABLE / WORLD_WRITABLE は危険）
grep -rn --include='*.kt' --include='*.java' \
  -E 'MODE_WORLD_(READABLE|WRITABLE)' .

# 外部ストレージへの書き込み
grep -rn --include='*.kt' --include='*.java' \
  -E '(getExternalStorageDirectory|getExternalFilesDir|Environment\.DIRECTORY_)' .

# ログ出力の機密データ
grep -rn --include='*.kt' --include='*.java' \
  -E 'Log\.(d|v|i|w|e|wtf)\(' . | \
  grep -iE '(password|token|secret|key|credential|bearer|session)'

# SQLite の平文データベース
grep -rn --include='*.kt' --include='*.java' \
  -E '(SQLiteDatabase\.openOrCreateDatabase|openOrCreateDatabase|SQLiteOpenHelper)' .

# クリップボードへのコピー
grep -rn --include='*.kt' --include='*.java' \
  -E '(ClipboardManager|setPrimaryClip|ClipData\.newPlainText)' .

# android:allowBackup 設定
grep -rn --include='AndroidManifest.xml' \
  -E 'android:allowBackup\s*=\s*"true"' .
```

## MASVS-CRYPTO: 暗号

### 検査対象

- **弱いアルゴリズム**: MD5, SHA1（署名用途）, DES, 3DES, RC4, ECB モード
- **Android KeyStore**: 適切な鍵保管とアクセス制御
- **ハードコードされた鍵**: ソースコード内の暗号鍵・IV
- **乱数生成**: `java.util.Random` の暗号用途使用（`SecureRandom` を推奨）
- **鍵導出関数**: PBKDF2, Argon2 の適切な使用

```bash
# 弱い暗号アルゴリズム
grep -rn --include='*.kt' --include='*.java' \
  -iE '(getInstance\s*\(\s*"(DES|DESede|RC4|RC2|Blowfish|MD5|SHA-1)"|AES/ECB|DES/ECB)' .

# ECB モードの使用（パターン漏洩リスク）
grep -rn --include='*.kt' --include='*.java' \
  -E 'Cipher\.getInstance\s*\(\s*"[^"]*ECB' .

# ハードコードされた暗号鍵
grep -rn --include='*.kt' --include='*.java' \
  -E '(val|var|final|static)\s+(key|secret|iv|nonce|aesKey|secretKey)\s*[:=]\s*"[^"]{8,}"' .

# java.util.Random の暗号用途使用（SecureRandom を推奨）
grep -rn --include='*.kt' --include='*.java' \
  -E 'java\.util\.Random|new\s+Random\(' .

# Android KeyStore の使用確認
grep -rn --include='*.kt' --include='*.java' \
  -E '(KeyStore\.getInstance\s*\(\s*"AndroidKeyStore"|KeyGenParameterSpec|setUserAuthenticationRequired)' .

# 弱いハッシュアルゴリズム
grep -rn --include='*.kt' --include='*.java' \
  -E 'MessageDigest\.getInstance\s*\(\s*"(MD5|SHA-1)"\)' .
```

## MASVS-AUTH: 認証

### 検査対象

- **BiometricPrompt**: 適切な生体認証の実装と CryptoObject の使用
- **ローカル認証**: 生体認証のフォールバック（デバイスクレデンシャル）の安全性
- **トークン管理**: アクセストークン・リフレッシュトークンの KeyStore 保存
- **セッション制御**: タイムアウト、バックグラウンド時の再認証
- **CryptoObject**: 生体認証と暗号操作の紐付け（認証バイパス防止）

```bash
# BiometricPrompt 実装
grep -rn --include='*.kt' --include='*.java' \
  -E '(BiometricPrompt|BiometricManager|canAuthenticate|authenticate\s*\()' .

# CryptoObject の使用確認（未使用は認証バイパスリスク）
grep -rn --include='*.kt' --include='*.java' \
  -E '(CryptoObject|BiometricPrompt\.CryptoObject)' .

# 生体認証のフォールバック設定
grep -rn --include='*.kt' --include='*.java' \
  -E '(setAllowedAuthenticators|BIOMETRIC_STRONG|BIOMETRIC_WEAK|DEVICE_CREDENTIAL)' .

# FingerprintManager（非推奨 API の検出）
grep -rn --include='*.kt' --include='*.java' \
  -E '(FingerprintManager|FingerprintManagerCompat)' .

# トークンの保存箇所
grep -rn --include='*.kt' --include='*.java' \
  -iE '(access_token|refresh_token|auth_token|bearer)' . | \
  grep -iE '(put|save|store|write|edit\(\))'
```

## MASVS-NETWORK: ネットワーク

### 検査対象

- **Network Security Config**: `network_security_config.xml` の設定
- **Cleartext 通信**: `cleartextTrafficPermitted` の有効化
- **Certificate Pinning**: ピン留めの実装（OkHttp CertificatePinner, Network Security Config）
- **カスタム TrustManager**: `X509TrustManager` の全証明書受け入れ
- **HostnameVerifier**: ホスト名検証の無効化

```bash
# Network Security Config の確認
find . -name 'network_security_config.xml' \
  -exec cat {} \;

# Cleartext 通信の許可
grep -rn --include='AndroidManifest.xml' \
  -E '(usesCleartextTraffic\s*=\s*"true"|cleartextTrafficPermitted\s*=\s*"true")' .

grep -rn --include='network_security_config.xml' \
  -E 'cleartextTrafficPermitted\s*=\s*"true"' .

# カスタム TrustManager（全証明書受け入れ = 危険）
grep -rn --include='*.kt' --include='*.java' \
  -E '(X509TrustManager|TrustManager|checkServerTrusted|getAcceptedIssuers)' .

# HostnameVerifier の無効化（全ホスト名許可 = 危険）
grep -rn --include='*.kt' --include='*.java' \
  -E '(ALLOW_ALL_HOSTNAME_VERIFIER|HostnameVerifier\s*\{|verify.*return\s+true)' .

# OkHttp Certificate Pinning
grep -rn --include='*.kt' --include='*.java' \
  -E '(CertificatePinner|certificatePinner|\.pin\s*\()' .

# HTTP URL の使用（cleartext）
grep -rn --include='*.kt' --include='*.java' \
  -E '"http://[^l][^o][^c][^a][^l]' . | grep -v '// '

# Network Security Config の参照
grep -rn --include='AndroidManifest.xml' \
  -E 'networkSecurityConfig' .
```

## MASVS-PLATFORM: プラットフォーム連携

### 検査対象

- **Intent フィルター**: 暗黙的 Intent の受信、入力検証
- **Deep Links / App Links**: URL パラメータの検証不足
- **WebView**: `setJavaScriptEnabled`, `addJavascriptInterface`, `setAllowFileAccess`
- **Content Provider**: `exported="true"` のプロバイダーと権限制御
- **Broadcast Receiver**: `exported="true"` のレシーバーとパーミッション
- **PendingIntent**: `FLAG_IMMUTABLE` / `FLAG_MUTABLE` の適切な使用
- **Activity / Service のエクスポート**: 不要なコンポーネントの公開

```bash
# exported コンポーネントの確認
grep -rn --include='AndroidManifest.xml' \
  -E 'android:exported\s*=\s*"true"' .

# Intent フィルター付きコンポーネント
grep -rn --include='AndroidManifest.xml' -A 5 \
  '<intent-filter>' .

# Deep Links の定義
grep -rn --include='AndroidManifest.xml' \
  -E '(android:scheme|android:host|android:pathPrefix)' .

# Intent データの未検証使用
grep -rn --include='*.kt' --include='*.java' \
  -E '(getIntent\(\)|intent\.(getStringExtra|getData|getAction|getExtras))' .

# WebView の危険な設定
grep -rn --include='*.kt' --include='*.java' \
  -E '(setJavaScriptEnabled\s*\(\s*true|addJavascriptInterface|setAllowFileAccess\s*\(\s*true|setAllowFileAccessFromFileURLs|setAllowUniversalAccessFromFileURLs)' .

# Content Provider のエクスポート
grep -rn --include='AndroidManifest.xml' -B 2 -A 5 \
  '<provider' . | grep -E '(exported|authorities|permission|readPermission|writePermission)'

# PendingIntent のフラグ確認（FLAG_MUTABLE は危険な場合あり）
grep -rn --include='*.kt' --include='*.java' \
  -E '(PendingIntent\.(getActivity|getBroadcast|getService|getForegroundService)|FLAG_MUTABLE|FLAG_IMMUTABLE)' .

# Broadcast Receiver のパーミッション
grep -rn --include='*.kt' --include='*.java' \
  -E '(registerReceiver|sendBroadcast|sendOrderedBroadcast)' .
```

## MASVS-CODE: コード品質

### 検査対象

- **ProGuard/R8**: 難読化設定の確認（`minifyEnabled`、`proguard-rules.pro`）
- **デバッグフラグ**: `android:debuggable="true"` の本番残存
- **StrictMode**: 本番ビルドでの有効化
- **依存ライブラリ**: 既知の脆弱性を含むライブラリ
- **入力検証**: 外部入力（Intent, Deep Link, Content Provider）のサニタイズ
- **WebView のリモートデバッグ**: `setWebContentsDebuggingEnabled(true)` の残存

```bash
# ProGuard/R8 設定
grep -rn --include='build.gradle' --include='build.gradle.kts' \
  -E '(minifyEnabled|isMinifyEnabled|proguardFiles|shrinkResources)' .

# デバッグフラグの残存
grep -rn --include='AndroidManifest.xml' \
  -E 'android:debuggable\s*=\s*"true"' .

# StrictMode の本番残存
grep -rn --include='*.kt' --include='*.java' \
  -E '(StrictMode\.setThreadPolicy|StrictMode\.setVmPolicy|StrictMode\.ThreadPolicy)' .

# WebView リモートデバッグの有効化
grep -rn --include='*.kt' --include='*.java' \
  -E 'setWebContentsDebuggingEnabled\s*\(\s*true' .

# デバッグログの残存
grep -rn --include='*.kt' --include='*.java' \
  -E '(BuildConfig\.DEBUG|isDebuggable|debuggable)' . | \
  grep -v 'if.*BuildConfig\.DEBUG'

# Gradle 依存の脆弱性確認
find . -name 'build.gradle' -o -name 'build.gradle.kts' | \
  head -5 | xargs grep -E 'implementation|api|compileOnly' 2>/dev/null
```

## MASVS-RESILIENCE: 耐タンパー性

### 検査対象

- **Root 検出**: RootBeer 等のライブラリ、手動検出ロジック
- **タンパー検出**: APK 署名の検証、Installer パッケージの確認
- **エミュレータ検出**: Build プロパティ、センサー有無のチェック
- **デバッガ検出**: `isDebuggerConnected()`, TracerPid の確認
- **Frida 検出**: Frida サーバーのポート・プロセスの検出
- **リバースエンジニアリング対策**: 文字列の難読化、リフレクション対策

```bash
# Root 検出の実装
grep -rn --include='*.kt' --include='*.java' \
  -iE '(isRooted|rootBeer|RootTools|checkForSuBinary|/system/app/Superuser|/system/xbin/su|com\.topjohnwu\.magisk)' .

# エミュレータ検出
grep -rn --include='*.kt' --include='*.java' \
  -iE '(isEmulator|Build\.(FINGERPRINT|MODEL|MANUFACTURER|BRAND|DEVICE|PRODUCT).*generic|goldfish|ranchu|sdk_gphone|google_sdk)' .

# デバッガ検出
grep -rn --include='*.kt' --include='*.java' \
  -E '(Debug\.isDebuggerConnected|waitForDebugger|TracerPid|android\.os\.Debug)' .

# Frida 検出
grep -rn --include='*.kt' --include='*.java' \
  -iE '(frida|27042|fridaserver|libfrida|xposed|de\.robv\.android\.xposed)' .

# APK 署名検証
grep -rn --include='*.kt' --include='*.java' \
  -E '(PackageManager\.GET_SIGNATURES|GET_SIGNING_CERTIFICATES|PackageInfo.*signatures|getPackageInfo)' .

# Installer パッケージの確認（サイドロード検出）
grep -rn --include='*.kt' --include='*.java' \
  -E '(getInstallerPackageName|getInstallSourceInfo|com\.android\.vending)' .
```

## MASVS-PRIVACY: プライバシー

### 検査対象

- **Android パーミッション**: 不要な危険パーミッション（`DANGEROUS` レベル）の要求
- **位置情報**: 前景/背景の位置情報アクセス、精度の最小化
- **広告 ID**: Google Advertising ID の使用と代替
- **データ収集**: 分析 SDK、トラッカーの使用状況
- **プライバシーインジケータ**: カメラ・マイク使用時のインジケータ対応

```bash
# 危険パーミッションの要求
grep -rn --include='AndroidManifest.xml' \
  -E '(READ_CONTACTS|READ_CALL_LOG|READ_SMS|RECORD_AUDIO|CAMERA|ACCESS_FINE_LOCATION|ACCESS_BACKGROUND_LOCATION|READ_EXTERNAL_STORAGE|READ_MEDIA_IMAGES|READ_PHONE_STATE|BODY_SENSORS)' .

# 位置情報の使用
grep -rn --include='*.kt' --include='*.java' \
  -E '(LocationManager|FusedLocationProviderClient|requestLocationUpdates|getLastKnownLocation|ACCESS_FINE_LOCATION|ACCESS_COARSE_LOCATION)' .

# 背景位置情報アクセス
grep -rn --include='AndroidManifest.xml' \
  -E 'ACCESS_BACKGROUND_LOCATION' .

# 広告 ID の使用
grep -rn --include='*.kt' --include='*.java' \
  -E '(AdvertisingIdClient|getAdvertisingIdInfo|advertisingId)' .

# 分析 SDK の検出
grep -rn --include='build.gradle' --include='build.gradle.kts' \
  -iE '(firebase-analytics|com\.google\.firebase|com\.facebook\.android|com\.adjust\.sdk|io\.branch|com\.appsflyer)' .

# カメラ・マイクの使用
grep -rn --include='*.kt' --include='*.java' \
  -E '(CameraManager|Camera\.open|MediaRecorder|AudioRecord)' .
```

## Android 検査チェックリスト

- [ ] SharedPreferences に機密データが平文で保存されていない（EncryptedSharedPreferences を使用）
- [ ] 外部ストレージに機密データが書き込まれていない
- [ ] `android:allowBackup="false"` が設定されている
- [ ] ログに機密データが出力されていない（Release ビルドでログ無効化）
- [ ] Network Security Config が適切に設定されている
- [ ] `cleartextTrafficPermitted` が false に設定されている
- [ ] Certificate Pinning が実装されている
- [ ] カスタム TrustManager が全証明書を受け入れていない
- [ ] HostnameVerifier が正しくホスト名を検証している
- [ ] 不要なコンポーネントが `exported="false"` に設定されている
- [ ] Intent データが検証・サニタイズされている
- [ ] WebView で `addJavascriptInterface` が最小限に使用されている
- [ ] WebView のリモートデバッグが本番で無効化されている
- [ ] Content Provider に適切なパーミッションが設定されている
- [ ] PendingIntent に `FLAG_IMMUTABLE` が使用されている
- [ ] BiometricPrompt で CryptoObject が使用されている
- [ ] 弱い暗号アルゴリズム（MD5, SHA1, DES, ECB モード）が使用されていない
- [ ] 暗号鍵がハードコードされていない（Android KeyStore を使用）
- [ ] `SecureRandom` が暗号用途に使用されている
- [ ] ProGuard/R8 による難読化が有効化されている
- [ ] `android:debuggable="false"` が設定されている
- [ ] Root 検出が実装されている（高セキュリティアプリの場合）
- [ ] 不要な危険パーミッションが要求されていない
- [ ] 背景位置情報アクセスが最小限に抑えられている
