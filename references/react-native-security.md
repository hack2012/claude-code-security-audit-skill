# React Native Security Testing Reference

React Native アプリケーション向けセキュリティ検査ガイド。OWASP MASVS v2 に基づくクロスプラットフォーム固有のリスクを網羅。

## データ保存

### 検査対象

- **AsyncStorage**: 平文での機密データ保存（暗号化なし）
- **react-native-keychain**: Keychain / KeyStore を利用した安全な保存
- **MMKV**: `react-native-mmkv` のデータ暗号化設定
- **Realm**: Realm データベースの暗号化有無
- **expo-secure-store**: Expo 環境でのセキュアストレージ
- **ログ出力**: `console.log` / `console.warn` での機密データ出力
- **クリップボード**: `@react-native-clipboard/clipboard` による機密データコピー

```bash
# AsyncStorage への機密データ保存
grep -rn --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' \
  -E '(AsyncStorage\.(setItem|getItem|mergeItem)|@react-native-async-storage)' . | \
  grep -iE '(password|token|secret|key|credential|session|auth|pin)'

# AsyncStorage の使用箇所
grep -rn --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' \
  -E 'AsyncStorage\.(setItem|multiSet|mergeItem)' .

# react-native-keychain の使用確認（推奨パターン）
grep -rn --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' \
  -E '(Keychain|setGenericPassword|getGenericPassword|setInternetCredentials|react-native-keychain)' .

# MMKV の暗号化設定確認
grep -rn --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' \
  -E '(MMKV|useMMKV|mmkvStorage|encryptionKey)' .

# Realm の暗号化設定
grep -rn --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' \
  -E '(Realm\.open|new\s+Realm|encryptionKey|realm)' . | \
  grep -iE '(encryption|key|config)'

# ログ出力の機密データ
grep -rn --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' \
  -E 'console\.(log|warn|info|debug|error)\(' . | \
  grep -iE '(password|token|secret|key|credential|bearer|session)'

# クリップボードへのコピー
grep -rn --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' \
  -E '(Clipboard\.setString|setStringAsync|@react-native-clipboard)' .

# expo-secure-store の使用
grep -rn --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' \
  -E '(SecureStore|expo-secure-store|setItemAsync|getItemAsync)' .
```

## ネットワーク

### 検査対象

- **fetch / axios**: HTTPS の使用、Cleartext 通信の検出
- **Certificate Pinning**: `react-native-ssl-pinning`, TrustKit の実装
- **API キーの露出**: リクエストヘッダー・URL 内のキー
- **GraphQL**: クエリの深度制限、Introspection の無効化
- **WebSocket**: `wss://` の使用

```bash
# HTTP（非 HTTPS）URL の使用
grep -rn --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' \
  -E "fetch\s*\(\s*['\`\"]http://[^l][^o][^c][^a][^l]" .

grep -rn --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' \
  -E "(baseURL|baseUrl|BASE_URL)\s*[:=]\s*['\`\"]http://" .

# axios の設定
grep -rn --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' \
  -E '(axios\.create|axios\.(get|post|put|delete)|baseURL)' .

# Certificate Pinning の実装
grep -rn --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' \
  -E '(ssl-pinning|react-native-ssl-pinning|TrustKit|certificatePinning|pinning)' .

# API キーのハードコード
grep -rn --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' \
  -E "(Authorization|X-Api-Key|api[_-]?key)\s*[:=]\s*['\`\"]" . | \
  grep -v 'process\.env\|Config\.\|ENV\.'

# WebSocket の暗号化
grep -rn --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' \
  -E "new\s+WebSocket\s*\(\s*['\`\"]ws://" .

# GraphQL Introspection
grep -rn --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' \
  -E '(__schema|__type|introspection)' .

# Android Network Security Config
find . -path '*/android/*' -name 'network_security_config.xml' \
  -exec cat {} \;

# iOS ATS 設定
find . -path '*/ios/*' -name 'Info.plist' -not -path '*/Pods/*' \
  -exec grep -A 5 'NSAppTransportSecurity' {} +
```

## コード保護

### 検査対象

- **Hermes バイトコード**: Hermes エンジンの有効化確認
- **CodePush セキュリティ**: OTA 更新の署名検証
- **JS バンドル保護**: ソースコードの難読化
- **__DEV__ フラグ**: デバッグコードのガード
- **ソースマップ**: 本番での公開リスク

```bash
# Hermes エンジンの有効化確認
grep -rn --include='build.gradle' --include='build.gradle.kts' \
  -E '(hermesEnabled|enableHermes)' .

# __DEV__ フラグの使用
grep -rn --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' \
  -E '__DEV__' .

# __DEV__ ガード外のデバッグコード
grep -rn --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' \
  -E 'console\.(log|warn|debug|info)\(' . | \
  grep -v '__DEV__\|// \|test\|spec\|mock'

# CodePush の設定
grep -rn --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' \
  -E '(codePush|CodePush|code-push|react-native-code-push)' .

# CodePush の署名検証
grep -rn --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' \
  -E '(publicKey|codePushPublicKey|CodePushPublicKey)' .

# ソースマップの生成設定
grep -rn --include='metro.config.js' --include='metro.config.ts' \
  -E '(sourcemap|sourceMap|devtool)' .

# React Native の難読化設定
grep -rn --include='package.json' \
  -E '(obfuscate|javascript-obfuscator|react-native-obfuscating-transformer|metro-minify)' .

# Flipper の本番残存
grep -rn --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' \
  -E '(flipper|react-native-flipper|addPlugin.*Flipper)' .

grep -rn --include='*.java' --include='*.kt' \
  -E '(ReactNativeFlipper|FlipperClient|initializeFlipper)' .
```

## Native Module セキュリティ

### 検査対象

- **Bridge セキュリティ**: Native Module のメソッド公開範囲
- **TurboModules**: 新アーキテクチャでのセキュリティ考慮
- **ネイティブコード脆弱性**: メモリ管理、入力検証
- **サードパーティ Native Module**: 信頼性の検証

```bash
# Native Module の定義（Android）
grep -rn --include='*.java' --include='*.kt' \
  -E '(@ReactMethod|ReactContextBaseJavaModule|ReactMethod|TurboModule)' .

# Native Module の定義（iOS）
grep -rn --include='*.m' --include='*.mm' --include='*.swift' \
  -E '(RCT_EXPORT_METHOD|RCT_EXPORT_MODULE|RCTBridgeModule)' .

# Native Module から呼び出される機密操作
grep -rn --include='*.java' --include='*.kt' \
  -E '@ReactMethod' -A 5 . | \
  grep -iE '(password|token|secret|key|credential|encrypt|decrypt|auth)'

# Native Module のリスト確認
grep -rn --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' \
  -E '(NativeModules\.|requireNativeComponent|TurboModuleRegistry)' .

# サードパーティ Native Module の確認
grep -rn --include='package.json' \
  -E '"react-native-' . | head -20
```

## 認証

### 検査対象

- **生体認証**: `react-native-biometrics`, `expo-local-authentication` の実装
- **トークン保存**: リフレッシュトークンの安全な保存
- **セッション管理**: タイムアウト、バックグラウンド時の再認証
- **認証状態管理**: Context / Redux での認証状態の保護

```bash
# 生体認証実装
grep -rn --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' \
  -E '(react-native-biometrics|ReactNativeBiometrics|biometricKeysExist|simplePrompt|createSignature|expo-local-authentication|authenticateAsync)' .

# トークンの保存方法
grep -rn --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' \
  -iE '(access.?token|refresh.?token|auth.?token|bearer)' . | \
  grep -iE '(setItem|save|store|write|set\()'

# セッション管理
grep -rn --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' \
  -E '(sessionTimeout|tokenExpir|refreshToken|isAuthenticated|authState)' .

# AppState によるバックグラウンド検出
grep -rn --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' \
  -E '(AppState\.addEventListener|appState.*background|appStateChange)' .
```

## Deep Linking

### 検査対象

- **URL スキーム**: カスタムスキームの入力検証
- **Universal Links / App Links**: ドメイン検証の設定
- **パラメータ検証**: Deep Link パラメータのサニタイズ
- **Navigation**: 動的ルーティングのアクセス制御

```bash
# Deep Link の設定（React Navigation）
grep -rn --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' \
  -E '(linking|deepLink|Linking\.addEventListener|Linking\.getInitialURL|useURL|createURL)' .

# URL スキームの定義
grep -rn --include='AndroidManifest.xml' \
  -E '(android:scheme|android:host|android:pathPrefix)' .

find . -path '*/ios/*' -name 'Info.plist' -not -path '*/Pods/*' \
  -exec grep -A 3 'CFBundleURLSchemes' {} +

# Deep Link パラメータの使用
grep -rn --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' \
  -E '(Linking\.parse|url\.parse|useRoute|route\.params|getInitialURL)' .

# Navigation のアクセス制御
grep -rn --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' \
  -E '(PrivateRoute|AuthNavigator|isAuthenticated.*navigate|beforeRemove|useAuth)' .

# Universal Links の apple-app-site-association
find . -name 'apple-app-site-association' -o -name 'assetlinks.json' | head -5
```

## デバッグ / リリース

### 検査対象

- **__DEV__ フラグ**: 開発専用コードの分離
- **デバッグ検出**: Release ビルドでのデバッグ機能の無効化
- **Flipper**: 本番ビルドでの Flipper 除去
- **React DevTools**: 本番での DevTools 無効化
- **LogBox**: エラーオーバーレイの無効化

```bash
# デバッグ専用コードの確認
grep -rn --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' \
  -E 'if\s*\(\s*__DEV__\s*\)' .

# console 文の残存（Release では除去推奨）
grep -rn --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' \
  -c 'console\.(log|warn|debug|info|error)\(' . | \
  grep -v ':0$' | sort -t: -k2 -nr | head -10

# Flipper の残存確認
grep -rn --include='package.json' \
  -E 'react-native-flipper' .

# babel-plugin-transform-remove-console の設定
grep -rn --include='babel.config.js' --include='babel.config.ts' --include='.babelrc' \
  -E '(transform-remove-console|remove-console)' .

# android:debuggable の確認
grep -rn --include='AndroidManifest.xml' \
  -E 'android:debuggable\s*=\s*"true"' .

# React DevTools の無効化
grep -rn --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' \
  -E '(connectToDevTools|DevTools|reactDevTools)' .

# LogBox の設定
grep -rn --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' \
  -E '(LogBox\.ignoreLogs|LogBox\.ignoreAllLogs)' .
```

## 依存セキュリティ

### 検査対象

- **npm audit**: JavaScript 依存の脆弱性
- **ネイティブ依存**: CocoaPods / Gradle のセキュリティ
- **サプライチェーン**: 悪意のあるパッケージの検出
- **バージョン固定**: lock ファイルの管理

```bash
# npm audit の実行
npm audit --json 2>/dev/null | head -50

# package-lock.json / yarn.lock の存在確認
ls -la package-lock.json yarn.lock pnpm-lock.yaml 2>/dev/null

# 依存の総数確認
grep -c '"react-native' package.json 2>/dev/null

# postinstall スクリプトの確認（サプライチェーン攻撃リスク）
grep -rn --include='package.json' \
  -E '"(preinstall|postinstall|prepare|prepublish)"' .

# native 依存の確認（CocoaPods）
find . -path '*/ios/*' -name 'Podfile.lock' | head -3

# native 依存の確認（Gradle）
find . -path '*/android/*' -name 'build.gradle' | \
  xargs grep -E 'implementation|api\s' 2>/dev/null | head -20

# 非公式レジストリの検出
grep -rn -E '(registry\s*[:=]|@.*:registry)' .npmrc .yarnrc .yarnrc.yml 2>/dev/null

# Expo の設定確認
grep -rn --include='app.json' --include='app.config.js' --include='app.config.ts' \
  -E '(expo|plugins|scheme|permissions)' . | head -20
```

## 環境変数とシークレット

### 検査対象

- **ハードコードされたシークレット**: API キー、トークン、パスワード
- **.env ファイル**: `react-native-config`, `react-native-dotenv` の使用
- **app.json / app.config.js**: Expo 設定内のシークレット
- **.gitignore**: 機密ファイルの除外確認

```bash
# ハードコードされた API キー・シークレット
grep -rn --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' \
  -E "(const|let|var)\s+\w*(apiKey|apiSecret|appKey|appSecret|clientSecret|secretKey|privateKey)\s*=\s*['\`\"][^'\`\"]+['\`\"]" .

# .env ファイルの確認
find . -maxdepth 2 -name '.env' -o -name '.env.*' | head -10
grep -n '\.env' .gitignore 2>/dev/null

# react-native-config の使用
grep -rn --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' \
  -E '(react-native-config|Config\.\w+|import\s+Config\s+from)' .

# Google Services ファイル
find . -name 'google-services.json' -o -name 'GoogleService-Info.plist' | head -5

# Firebase 設定のハードコード
grep -rn --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' \
  -E '(apiKey|authDomain|databaseURL|projectId|storageBucket|messagingSenderId|appId)\s*[:=]' . | \
  grep -v 'process\.env\|Config\.\|ENV\.\|@type\|interface\|type '

# Sentry DSN の露出
grep -rn --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' \
  -E '(SENTRY_DSN|dsn.*sentry|sentry\.io)' .
```

## React Native 検査チェックリスト

- [ ] AsyncStorage に機密データが保存されていない（`react-native-keychain` を使用）
- [ ] ログに機密データが出力されていない（Release で console 文を除去）
- [ ] `babel-plugin-transform-remove-console` が設定されている
- [ ] HTTPS のみ使用され、HTTP 通信が存在しない
- [ ] Certificate Pinning が実装されている
- [ ] API キーがソースコード内にハードコードされていない
- [ ] `.env` ファイルが `.gitignore` に含まれている
- [ ] `google-services.json` / `GoogleService-Info.plist` が適切に管理されている
- [ ] Hermes エンジンが有効化されている（バイトコード化による保護）
- [ ] CodePush を使用する場合、署名検証が有効化されている
- [ ] `__DEV__` でデバッグコードが適切にガードされている
- [ ] Flipper が本番ビルドから除去されている
- [ ] `android:debuggable="false"` が設定されている
- [ ] Native Module のメソッドが最小限に公開されている
- [ ] Deep Link のパラメータが検証・サニタイズされている
- [ ] 生体認証が適切に実装されている（`react-native-biometrics`）
- [ ] トークンが Keychain / KeyStore に保存されている
- [ ] `npm audit` で脆弱な依存が検出されていない
- [ ] `postinstall` スクリプトが安全であることが確認されている
- [ ] lock ファイル（package-lock.json / yarn.lock）がコミットされている
- [ ] Android の Network Security Config が適切に設定されている
- [ ] iOS の ATS（App Transport Security）が有効化されている
- [ ] WebSocket が `wss://` を使用している
- [ ] ソースマップが本番で公開されていない
