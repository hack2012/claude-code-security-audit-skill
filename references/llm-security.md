# LLM / AI Security Reference

OWASP Top 10 for LLM Applications (2025) に基づく LLM アプリケーションのセキュリティ検査ガイド。

## LLM01: Prompt Injection（プロンプトインジェクション）

### リスク

攻撃者がプロンプトを操作し、LLM の動作を意図しない方向に誘導する。直接インジェクション（ユーザー入力）と間接インジェクション（外部データソース経由）がある。

### 検査パターン

```bash
# ユーザー入力がプロンプトに直接結合されている箇所
grep -rn --include='*.{ts,js,py,rb,go}' \
  -E '(prompt|system_message|messages).*(\+|concat|format|f['\''"]|template|`\$\{)' \
  . 2>/dev/null | grep -v node_modules

# プロンプトテンプレートの検出
grep -rn --include='*.{ts,js,py}' \
  -E '(ChatPromptTemplate|PromptTemplate|SystemMessage|HumanMessage)' \
  . 2>/dev/null | grep -v node_modules

# ユーザー入力のサニタイズ確認
grep -rn --include='*.{ts,js,py}' \
  -iE '(sanitize|escape|filter|validate).*prompt' \
  . 2>/dev/null | grep -v node_modules

# プロンプトガード / 入力フィルタリングの検出
grep -rn --include='*.{ts,js,py}' \
  -iE '(prompt.?guard|input.?filter|content.?filter|moderation|guardrail)' \
  . 2>/dev/null | grep -v node_modules
```

**対策**:
- システムプロンプトとユーザー入力を明確に分離
- 入力の長さ制限とサニタイズ
- LLM 出力の検証（出力ガードレール）
- 権限の最小化（LLM が実行できるアクションを制限）

## LLM02: Insecure Output Handling（安全でない出力処理）

### リスク

LLM の出力を検証なしにアプリケーションに渡すと、XSS、SSRF、コマンドインジェクション等の二次攻撃が発生する。

```bash
# LLM 出力の直接 HTML 挿入（XSS リスク）
# dangerouslySetInnerHTML, innerHTML, v-html の使用箇所を確認
grep -rn --include='*.{ts,tsx,js,jsx}' \
  -E '(innerHTML|v-html)' \
  . 2>/dev/null | grep -v node_modules

# LLM 出力の eval / exec 実行
grep -rn --include='*.{ts,js,py}' \
  -E '(eval\(|exec\(|Function\(|subprocess).*\b(response|output|result|completion|content)\b' \
  . 2>/dev/null | grep -v node_modules

# LLM 出力を URL として使用（SSRF リスク）
grep -rn --include='*.{ts,js,py}' \
  -E '(fetch|axios|requests\.(get|post)|urllib|http\.get).*\b(response|output|result|content)\b' \
  . 2>/dev/null | grep -v node_modules

# Markdown / HTML レンダリングの検出
grep -rn --include='*.{ts,tsx,js,jsx}' \
  -E '(react-markdown|remark|rehype|marked|DOMPurify|sanitize-html)' \
  . 2>/dev/null | grep -v node_modules
```

## LLM03: Training Data Poisoning（学習データの汚染）

### リスク

ファインチューニングデータや RAG のデータソースが汚染されると、モデルの出力が操作される。

```bash
# ファインチューニングデータの検出
find . -name '*.jsonl' -o -name 'training_data*' -o -name 'finetune*' \
  -o -name 'dataset*' 2>/dev/null | grep -v node_modules | head -10

# ファインチューニング API の使用
grep -rn --include='*.{ts,js,py}' \
  -E '(fine.?tun|FineTuning|create_fine_tuning|training_file)' \
  . 2>/dev/null | grep -v node_modules

# データ検証パイプラインの確認
grep -rn --include='*.{ts,js,py}' \
  -iE '(data.?valid|schema.?valid|input.?check|data.?clean)' \
  . 2>/dev/null | grep -v node_modules
```

## LLM04: Model Denial of Service（モデル DoS）

### リスク

大量のトークン消費や繰り返しリクエストにより、API コストの急増やサービス停止が発生する。

```bash
# トークン制限の設定確認
grep -rn --include='*.{ts,js,py}' \
  -E '(max_tokens|maxTokens|max_completion_tokens|token.?limit|max_length)' \
  . 2>/dev/null | grep -v node_modules

# レート制限の実装確認
grep -rn --include='*.{ts,js,py}' \
  -iE '(rate.?limit|throttle|limiter|RateLimiter|slowDown)' \
  . 2>/dev/null | grep -v node_modules

# コスト制限 / 予算制御の確認
grep -rn --include='*.{ts,js,py}' \
  -iE '(budget|cost.?limit|spending.?limit|usage.?limit|max.?cost)' \
  . 2>/dev/null | grep -v node_modules

# 入力長の制限確認
grep -rn --include='*.{ts,js,py}' \
  -iE '(input.?length|max.?input|content.?length|truncat)' \
  . 2>/dev/null | grep -v node_modules
```

## LLM05: Supply Chain Vulnerabilities（サプライチェーン）

### リスク

悪意あるモデル、改ざんされた AI ライブラリ、不正なプラグインにより、アプリケーション全体が侵害される。

```bash
# AI/ML ライブラリの依存関係確認
grep -rn --include='package.json' \
  -E '(openai|@anthropic-ai|langchain|llamaindex|@langchain|ai|@ai-sdk)' \
  . 2>/dev/null | grep -v node_modules

grep -rn --include='requirements*.txt' --include='pyproject.toml' \
  -E '(openai|anthropic|langchain|llama.index|transformers|torch|huggingface)' \
  . 2>/dev/null

# モデルファイルの直接ダウンロード（検証なし）
grep -rn --include='*.{ts,js,py}' \
  -E '(download.*model|from_pretrained|AutoModel|pipeline\()' \
  . 2>/dev/null | grep -v node_modules

# Pickle / 非安全なデシリアライゼーション
grep -rn --include='*.py' \
  -E '(pickle\.load|torch\.load|joblib\.load|np\.load.*allow_pickle)' \
  . 2>/dev/null | grep -v node_modules
```

## LLM06: Sensitive Information Disclosure（機密情報の漏洩）

### リスク

プロンプトに含まれる PII（個人情報）、システムプロンプトの漏洩、モデルの記憶による機密データ出力。

```bash
# PII がプロンプトに含まれる可能性
grep -rn --include='*.{ts,js,py}' \
  -iE '(user\.(email|name|phone|address|ssn)|personal|pii|credit.?card).*prompt' \
  . 2>/dev/null | grep -v node_modules

# システムプロンプトの保護確認
grep -rn --include='*.{ts,js,py}' \
  -iE '(system.?prompt|system.?message|SYSTEM_PROMPT)' \
  . 2>/dev/null | grep -v node_modules

# ログへのプロンプト / レスポンス記録
grep -rn --include='*.{ts,js,py}' \
  -E '(console\.log|logger\.|logging\.).*\b(prompt|message|completion|response)\b' \
  . 2>/dev/null | grep -v node_modules

# PII マスキング / 匿名化の実装
grep -rn --include='*.{ts,js,py}' \
  -iE '(anonymize|mask|redact|scrub|pii.?filter|presidio)' \
  . 2>/dev/null | grep -v node_modules
```

## LLM07: Insecure Plugin Design（安全でないプラグイン設計）

### リスク

LLM が外部ツール / Function Calling を使用する際、入力の検証不足や過剰な権限が脆弱性を生む。

```bash
# Function Calling / Tool Use の定義
grep -rn --include='*.{ts,js,py}' \
  -E '(tools|functions|function_call|tool_choice|tool_use)' \
  . 2>/dev/null | grep -v node_modules | head -30

# ツール実行の入力検証
grep -rn --include='*.{ts,js,py}' \
  -iE '(tool.?input|function.?arg|parameter.?valid|schema.?valid)' \
  . 2>/dev/null | grep -v node_modules

# LangChain / LlamaIndex のツール定義
grep -rn --include='*.{ts,js,py}' \
  -E '(Tool\(|StructuredTool|BaseTool|FunctionTool|QueryEngineTool)' \
  . 2>/dev/null | grep -v node_modules

# ツールが実行するデータベース / ファイル操作
grep -rn --include='*.{ts,js,py}' \
  -E '(tool|agent).*(execute|run|invoke|call)' \
  . 2>/dev/null | grep -v node_modules | head -20
```

## LLM08: Excessive Agency（過剰なエージェント権限）

### リスク

LLM エージェントに過剰なアクション権限（データ削除、メール送信、支払い実行等）を付与すると、ハルシネーションやプロンプトインジェクション経由で意図しない操作が実行される。

```bash
# エージェントフレームワークの使用検出
grep -rn --include='*.{ts,js,py}' \
  -E '(AgentExecutor|create_agent|initialize_agent|ReActAgent|AutoGPT|CrewAI)' \
  . 2>/dev/null | grep -v node_modules

# 自律実行の確認（human-in-the-loop なし）
grep -rn --include='*.{ts,js,py}' \
  -iE '(auto.?execute|auto.?run|human.?in.?the.?loop|confirm|approval|require.?human)' \
  . 2>/dev/null | grep -v node_modules

# 危険なアクション（データ削除、メール送信等）
grep -rn --include='*.{ts,js,py}' \
  -iE '(delete|remove|drop|send.?email|transfer|payment|deploy)' \
  . 2>/dev/null | grep -v node_modules | \
  grep -iE '(tool|action|function|agent)' | head -20
```

## LLM09: Overreliance（過度な依存）

### リスク

LLM の出力を検証せずに信頼すると、ハルシネーションによる誤情報や不正確なコード生成がシステムに組み込まれる。

```bash
# ファクトチェック / 検証メカニズムの確認
grep -rn --include='*.{ts,js,py}' \
  -iE '(fact.?check|verify|validate.?output|confidence|certainty|ground.?truth)' \
  . 2>/dev/null | grep -v node_modules

# LLM 出力の直接使用（検証なし）
grep -rn --include='*.{ts,js,py}' \
  -E '(completion|response|output)\.(content|text|message)' \
  . 2>/dev/null | grep -v node_modules | head -20
```

## LLM10: Model Theft（モデル盗難）

### リスク

API キーの漏洩によるモデルの不正利用、プロプライエタリモデルファイルの流出。

```bash
# API キーのハードコード検出
grep -rn --include='*.{ts,js,py}' \
  -E '(OPENAI_API_KEY|ANTHROPIC_API_KEY|api.?key)\s*[:=]\s*['\''"][^'\''"{$]+['\''"]' \
  . 2>/dev/null | grep -v node_modules

# モデルファイルの検出
find . -name '*.gguf' -o -name '*.bin' -o -name '*.safetensors' \
  -o -name '*.onnx' -o -name '*.pt' -o -name '*.pth' \
  2>/dev/null | grep -v node_modules | head -10

# モデルファイルが Git 追跡されているか
git ls-files | grep -E '\.(gguf|bin|safetensors|onnx|pt|pth)$'

# API キーの環境変数管理確認
grep -rn --include='*.{ts,js,py}' \
  -E '(process\.env|os\.environ|os\.getenv).*(OPENAI|ANTHROPIC|API_KEY|LLM)' \
  . 2>/dev/null | grep -v node_modules
```

## RAG Security（検索拡張生成のセキュリティ）

### リスク

RAG パイプラインのデータソース汚染、ベクトル DB へのアクセス制御不備、Embedding インジェクション。

```bash
# ベクトル DB の使用検出
grep -rn --include='*.{ts,js,py}' \
  -E '(pinecone|weaviate|qdrant|chroma|milvus|pgvector|faiss|VectorStore)' \
  . 2>/dev/null | grep -v node_modules

# ベクトル DB のアクセス制御
grep -rn --include='*.{ts,js,py}' \
  -iE '(api.?key|auth|credential|token).*(pinecone|weaviate|qdrant|chroma)' \
  . 2>/dev/null | grep -v node_modules

# ドキュメントローダーの入力検証
grep -rn --include='*.{ts,js,py}' \
  -E '(DocumentLoader|TextLoader|PDFLoader|WebBaseLoader|DirectoryLoader|load_documents)' \
  . 2>/dev/null | grep -v node_modules

# Embedding の入力サニタイズ
grep -rn --include='*.{ts,js,py}' \
  -iE '(embed|embedding).*(sanitize|validate|filter|clean)' \
  . 2>/dev/null | grep -v node_modules
```

## MCP Security（Model Context Protocol）

### リスク

MCP サーバーが未検証のツール実行を許可すると、LLM 経由で任意のシステム操作が可能になる。

```bash
# MCP サーバー設定の検出
find . -name 'mcp*.json' -o -name '.mcp*' -o -name 'claude_desktop_config.json' \
  2>/dev/null | head -10

# MCP ツールの定義
grep -rn --include='*.{ts,js,py}' \
  -E '(McpServer|Server|tool\(|@mcp\.tool|ListToolsResult)' \
  . 2>/dev/null | grep -v node_modules | head -20

# MCP の認証・認可設定
grep -rn --include='*.{ts,js,py,json}' \
  -iE '(mcp.*(auth|token|credential|permission)|allowedTools|toolApproval)' \
  . 2>/dev/null | grep -v node_modules
```

## API Security（LLM API のセキュリティ）

```bash
# OpenAI / Anthropic SDK の使用
grep -rn --include='*.{ts,js,py}' \
  -E '(OpenAI|Anthropic|ChatOpenAI|ChatAnthropic)\(' \
  . 2>/dev/null | grep -v node_modules

# ストリーミングレスポンスの処理
grep -rn --include='*.{ts,js,py}' \
  -E '(stream|streaming|createStream|streamText|streamObject)' \
  . 2>/dev/null | grep -v node_modules | head -20

# API エンドポイントの認証
grep -rn --include='*.{ts,js,py}' \
  -E '(api|route|endpoint).*(chat|completion|generate|embed)' \
  . 2>/dev/null | grep -v node_modules | head -20

# トークンカウント / コスト追跡
grep -rn --include='*.{ts,js,py}' \
  -iE '(token.?count|usage|total_tokens|prompt_tokens|completion_tokens|tiktoken|cost.?track)' \
  . 2>/dev/null | grep -v node_modules
```

## OWASP Top 10 for LLM Applications 2025 クイックリファレンス

| Rank | カテゴリ | 主な検出パターン |
|------|---------|-----------------|
| LLM01 | Prompt Injection | ユーザー入力のプロンプト直接結合、入力フィルタなし |
| LLM02 | Insecure Output Handling | LLM 出力の HTML 直接挿入、eval 実行 |
| LLM03 | Training Data Poisoning | ファインチューニングデータの検証不足 |
| LLM04 | Model DoS | トークン制限なし、レート制限なし |
| LLM05 | Supply Chain | 未検証の AI ライブラリ、Pickle デシリアライズ |
| LLM06 | Sensitive Information Disclosure | PII のプロンプト送信、ログへの記録 |
| LLM07 | Insecure Plugin Design | ツール入力の検証不足、過剰な権限 |
| LLM08 | Excessive Agency | human-in-the-loop なし、自律実行 |
| LLM09 | Overreliance | 出力検証なし、ファクトチェック欠如 |
| LLM10 | Model Theft | API キーのハードコード、モデルファイル露出 |

## LLM セキュリティチェックリスト

### プロンプト・入出力

- [ ] ユーザー入力がプロンプトに直接結合されていない（テンプレートで分離）
- [ ] 入力長の制限が実装されている
- [ ] プロンプトインジェクション対策（入力フィルタリング / ガードレール）が実装されている
- [ ] LLM 出力が HTML / SQL / コマンドとして直接実行されていない
- [ ] LLM 出力のサニタイズ・検証が実装されている

### 認証・認可

- [ ] LLM API エンドポイントに認証が実装されている
- [ ] API キーが環境変数で管理されている（ハードコードなし）
- [ ] レート制限が実装されている
- [ ] トークン使用量の上限が設定されている
- [ ] コスト制御・予算制限が設定されている

### データ保護

- [ ] PII がプロンプトに含まれる場合、マスキング / 匿名化されている
- [ ] プロンプト / レスポンスのログに機密情報が含まれていない
- [ ] システムプロンプトの漏洩対策が実装されている
- [ ] ベクトル DB のアクセス制御が設定されている

### ツール・エージェント

- [ ] Function Calling / Tool Use の入力が検証されている
- [ ] ツールの権限が最小化されている
- [ ] 破壊的アクション（削除、送信等）に human-in-the-loop が実装されている
- [ ] MCP サーバーの認証・認可が設定されている

### サプライチェーン

- [ ] AI/ML ライブラリが最新バージョンに更新されている
- [ ] モデルファイルが Git にコミットされていない
- [ ] Pickle 等の非安全なデシリアライゼーションが使用されていない
- [ ] ファインチューニングデータの検証パイプラインが存在する
