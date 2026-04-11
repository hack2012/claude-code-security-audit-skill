# iOS Security Testing Reference

OWASP MASVS v2 / MASTG に基づく詳細検査ガイド。

## MASVS-STORAGE: データ保存

### 検査対象

- **NSUserDefaults**: 機密データ（トークン、パスワード、個人情報）の保存禁止
- **Keychain**: アクセス属性の適切性（`kSecAttrAccessibleWhenUnlockedThisDeviceOnly` 推奨）
- **SQLite/Realm/Core Data**: 暗号化の有無、WAL ファイルの保護
- **ファイルシステム**: Data Protection クラスの設定
- **クリップボード**: `UIPasteboard.general` への機密データコピー
- **バックアップ除外**: iTunes/iCloud バックアップからの機密ファイル除外
- **ログ出力**: `NSLog` / `os_log` / `print` での機密データ出力
- **スナップショット**: バックグラウンド遷移時のスクリーンショット保護

```bash
# NSUserDefaults への機密データ保存
grep -rn --include='*.swift' \
  -E 'UserDefaults\.(standard|suite)' . | \
  grep -iE '(password|token|secret|key|credential|session|auth)'

# Keychain アクセス属性
grep -rn --include='*.swift' --include='*.m' \
  -E 'kSecAttrAccessible' .

# ログ出力の機密データ
grep -rn --include='*.swift' \
  -E '(NSLog|os_log|print|debugPrint)\(.*' . | \
  grep -iE '(password|token|secret|key|credential|bearer)'

# Data Protection クラス
grep -rn --include='*.swift' --include='*.m' \
  -E '(NSFileProtection|FileProtectionType)' .

# クリップボード使用
grep -rn --include='*.swift' \
  -E 'UIPasteboard\.general\.(string|setValue|setData)' .
```

## MASVS-CRYPTO: 暗号

### 検査対象

- **弱いアルゴリズム**: MD5, SHA1（署名用途）, DES, 3DES, RC4
- **CryptoKit / CommonCrypto**: 適切な使用
- **鍵管理**: ハードコードされた暗号鍵、鍵導出関数の使用
- **Secure Enclave**: 生体認証と組み合わせた鍵保護
- **乱数生成**: `SecRandomCopyBytes` の使用（`arc4random` は暗号用途に不十分）

```bash
# 弱い暗号アルゴリズム
grep -rn --include='*.swift' --include='*.m' \
  -iE '(CC_MD5|CC_SHA1|kCCAlgorithmDES|kCCAlgorithm3DES|\.md5|\.sha1)' .

# ハードコードされた暗号鍵
grep -rn --include='*.swift' \
  -E '(let|var)\s+(key|secret|iv|nonce)\s*[:=]\s*"[^"]{8,}"' .

# 乱数生成
grep -rn --include='*.swift' --include='*.m' \
  -E '(arc4random|srand|rand\(\)|drand48)' .

# Secure Enclave 使用確認
grep -rn --include='*.swift' \
  -E '(SecureEnclave|\.secureEnclave|kSecAttrTokenIDSecureEnclave)' .
```

## MASVS-AUTH: 認証

### 検査対象

- **Local Authentication**: Touch ID / Face ID の実装
- **生体認証のフォールバック**: パスコードフォールバック時のセキュリティ
- **LAContext**: `evaluatePolicy` の使用と `evaluatedPolicyDomainState` の検証
- **トークン管理**: リフレッシュトークンの Keychain 保存
- **セッション制御**: タイムアウト、バックグラウンド時の再認証

```bash
# 生体認証実装
grep -rn --include='*.swift' \
  -E '(LAContext|canEvaluatePolicy|evaluatePolicy|biometryType)' .

# 生体認証ポリシー（deviceOwnerAuthentication はパスコードフォールバックあり）
grep -rn --include='*.swift' \
  -E '(deviceOwnerAuthenticationWithBiometrics|deviceOwnerAuthentication)' .

# Keychain でのトークン保存
grep -rn --include='*.swift' \
  -E '(SecItemAdd|SecItemUpdate|SecItemCopyMatching|SecItemDelete)' .
```

## MASVS-NETWORK: ネットワーク

### 検査対象

- **ATS (App Transport Security)**: `NSAllowsArbitraryLoads` の無効化確認
- **Certificate Pinning**: URLSession delegate または TrustKit の実装
- **Cleartext 通信**: HTTP（非 HTTPS）エンドポイントの使用
- **プロキシ検出**: 中間者攻撃への対策

```bash
# ATS 設定の確認
find . -name 'Info.plist' -not -path '*/Pods/*' -not -path '*/.build/*' \
  -exec grep -A 10 'NSAppTransportSecurity' {} +

# NSAllowsArbitraryLoads（全 HTTP 許可 = 危険）
find . -name 'Info.plist' -not -path '*/Pods/*' \
  -exec grep -l 'NSAllowsArbitraryLoads.*true' {} \;

# Certificate Pinning 実装
grep -rn --include='*.swift' \
  -E '(urlSession.*didReceive.*challenge|SecTrustEvaluate|TrustKit|pinnedDomains)' .

# HTTP URL の使用（cleartext）
grep -rn --include='*.swift' --include='*.m' \
  -E 'http://[^l][^o][^c][^a][^l]' . | grep -v '// '
```

## MASVS-PLATFORM: プラットフォーム連携

### 検査対象

- **Universal Links**: `apple-app-site-association` の設定、入力検証
- **Custom URL Schemes**: 未検証の URL パラメータ処理
- **WebView**: `WKWebView` の JavaScript 設定、`file://` アクセス
- **App Extensions**: データ共有のスコープ制限
- **UIPasteboard**: アプリ間データ漏洩
- **スクリーンショット防止**: `UITextField.isSecureTextEntry` の使用

```bash
# Universal Links / URL スキーム
grep -rn --include='*.swift' \
  -E '(application.*open.*url|userActivity.*webpageURL|NSUserActivity)' .

# URL スキームの入力検証
grep -rn --include='*.swift' \
  -E '(func\s+application.*open\s+url|UIApplication.*openURL)' .

# WebView 設定
grep -rn --include='*.swift' \
  -E '(WKWebView|WKWebViewConfiguration|javaScriptEnabled|allowFileAccessFromFileURLs)' .

# App Extensions のデータ共有
grep -rn --include='*.swift' \
  -E '(UserDefaults\(suiteName|FileManager.*containerURL.*appGroupIdentifier)' .
```

## MASVS-CODE: コード品質

### 検査対象

- **コンパイラ保護**: PIE, Stack Canaries, ARC
- **依存ライブラリ**: CocoaPods/SPM/Carthage の脆弱性
- **デバッグコード**: `#if DEBUG` ガード外のデバッグ機能
- **入力検証**: ディープリンク・IPC 経由の入力サニタイズ

```bash
# デバッグコードの残存
grep -rn --include='*.swift' \
  -E '(#if\s+DEBUG|debugPrint|assert\(|precondition\()' .

# CocoaPods の脆弱性確認
[ -f Podfile.lock ] && pod audit 2>/dev/null

# SPM 依存の確認
find . -name 'Package.resolved' -exec cat {} \;
```

## MASVS-RESILIENCE: 耐タンパー性

### 検査対象

- **Jailbreak 検出**: ファイルシステムチェック、Cydia URL スキーム
- **デバッガ検出**: `ptrace`, `sysctl` による検出
- **整合性チェック**: コード署名の検証
- **リバースエンジニアリング対策**: 文字列の難読化

```bash
# Jailbreak 検出の実装
grep -rn --include='*.swift' --include='*.m' \
  -E '(cydia|/Applications/Cydia|/usr/sbin/sshd|/bin/bash|jailbreak|isJailbroken)' .

# デバッガ検出
grep -rn --include='*.swift' --include='*.m' \
  -E '(ptrace|PT_DENY_ATTACH|sysctl|CTL_KERN|KERN_PROC)' .
```

## MASVS-PRIVACY: プライバシー

### 検査対象

- **ATT (App Tracking Transparency)**: `requestTrackingAuthorization` の実装
- **Privacy Manifest**: `PrivacyInfo.xcprivacy` の存在と内容
- **位置情報**: 使用目的の明示、精度の最小化
- **カメラ・マイク**: 使用目的の明示
- **データ最小化**: 必要最小限のデータ収集

```bash
# ATT 実装
grep -rn --include='*.swift' \
  -E '(ATTrackingManager|requestTrackingAuthorization|trackingAuthorizationStatus)' .

# Privacy Manifest
find . -name 'PrivacyInfo.xcprivacy' -not -path '*/Pods/*'

# 位置情報の使用
grep -rn --include='*.swift' \
  -E '(CLLocationManager|requestWhenInUseAuthorization|requestAlwaysAuthorization)' .

# Info.plist の使用目的記述
find . -name 'Info.plist' -not -path '*/Pods/*' \
  -exec grep -l 'NSLocationWhenInUseUsageDescription\|NSCameraUsageDescription\|NSMicrophoneUsageDescription' {} \;
```

## iOS 検査チェックリスト

- [ ] Keychain に適切なアクセス属性が設定されている
- [ ] NSUserDefaults に機密データが保存されていない
- [ ] ATS が有効で `NSAllowsArbitraryLoads` が false
- [ ] Certificate Pinning が実装されている
- [ ] 生体認証が Keychain ACL と連携している
- [ ] WebView で不要な JavaScript が無効化されている
- [ ] Universal Links の入力が検証されている
- [ ] ログに機密データが出力されていない
- [ ] バックグラウンド遷移時のスクリーンショットが保護されている
- [ ] Privacy Manifest が存在し、正確である
- [ ] 弱い暗号アルゴリズムが使用されていない
- [ ] デバッグコードが本番ビルドに含まれていない
