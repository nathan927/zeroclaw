<p align="center">
  <img src="zeroclaw.png" alt="ZeroClaw" width="200" />
</p>

<h1 align="center">ZeroClaw 🦀</h1>

<p align="center">
  <strong>零開銷。零妥協。100% Rust。100% 不鎖定。</strong><br>
  ⚡️ <strong>在 $10 硬體上運行，記憶體 < 5MB：比 OpenClaw 少 99% 記憶體，比 Mac mini 便宜 98%！</strong>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT" /></a>
  <a href="https://buymeacoffee.com/argenistherose"><img src="https://img.shields.io/badge/Buy%20Me%20a%20Coffee-Donate-yellow.svg?style=flat&logo=buy-me-a-coffee" alt="Buy Me a Coffee" /></a>
</p>

<p align="center">
  <a href="README.md">English</a> · <strong>繁體中文</strong>
</p>

快速、輕量、完全自主的 AI 助理基礎建設 — 隨處部署，隨意替換。

```
~3.4MB 二進位檔 · <10ms 啟動 · 1,017 測試 · 22+ 提供者 · 8 個 Trait · 全可插拔
```

### ✨ 特色

- 🏎️ **超輕量：** 記憶體佔用 < 5MB — 比 OpenClaw 核心小 99%
- 💰 **極低成本：** 可在 $10 硬體上運行 — 比 Mac mini 便宜 98%
- ⚡ **極速啟動：** 啟動速度快 400 倍，< 10ms（0.6GHz 處理器也僅需 1 秒以內）
- 🌍 **真正可攜式：** 單一自包含二進位檔，跨 ARM、x86、RISC-V

### 為什麼選擇 ZeroClaw

- **預設精簡：** 小型 Rust 二進位檔，快速啟動，低記憶體佔用
- **安全設計：** 配對機制、嚴格沙箱、明確白名單、工作區限定
- **完全可替換：** 核心系統皆為 Trait（提供者、頻道、工具、記憶體、隧道）
- **無綁定：** 支援 OpenAI 相容提供者 + 可插拔自訂端點

## 效能比較（ZeroClaw vs OpenClaw）

本地快速基準測試（macOS arm64，2026 年 2 月），已換算至 0.8GHz 邊緣硬體：

| | OpenClaw | NanoBot | PicoClaw | ZeroClaw 🦀 |
|---|---|---|---|---|
| **語言** | TypeScript | Python | Go | **Rust** |
| **記憶體** | > 1GB | > 100MB | < 10MB | **< 5MB** |
| **啟動（0.8GHz）** | > 500s | > 30s | < 1s | **< 10ms** |
| **檔案大小** | ~28MB (dist) | N/A (Scripts) | ~8MB | **3.4 MB** |
| **成本** | Mac Mini $599 | Linux SBC ~$50 | Linux Board $10 | **任何硬體 $10** |

## 快速開始

```bash
git clone https://github.com/nathan927/zeroclaw.git
cd zeroclaw
cargo build --release
cargo install --path . --force

# 快速設定（無互動提示）
zeroclaw onboard --api-key sk-... --provider openrouter

# 或互動式精靈
zeroclaw onboard --interactive

# 或僅快速修復頻道/白名單
zeroclaw onboard --channels-only

# 對話
zeroclaw agent -m "你好！"

# 互動模式
zeroclaw agent

# 啟動 Gateway（Webhook 伺服器）
zeroclaw gateway

# 啟動全自主運行模式
zeroclaw daemon

# 檢查狀態
zeroclaw status
```

> **開發替代方案（不安裝全域）：** 在命令前加上 `cargo run --release --`（例如：`cargo run --release -- status`）

### 升級現有安裝

```bash
cargo install --git https://github.com/nathan927/zeroclaw.git --force
```

一行指令自動拉取最新程式碼、編譯並安裝。舊的 `config.toml` 和所有資料完全相容，無需調整。

## Google OAuth 登入與配額輪換

ZeroClaw 支援 **Google OAuth Device Flow** 驗證，可直接用 Google 帳號使用 Gemini 提供者 — 不需要 API Key。多帳號時自動使用**配額感知負載均衡**。

### 用 Google 登入

```bash
zeroclaw google-auth login
```

執行後的流程：
1. 終端機顯示一個網址和驗證碼
2. 在瀏覽器開啟該網址並輸入驗證碼
3. Token 自動儲存至 `~/.zeroclaw/google-oauth-tokens.json`

重複執行 `login` 即可新增多個 Google 帳號。

### 運作原理

- **零設定** — Token 由 `GeminiProvider` 自動載入
- **自動刷新** — 過期的 Token 會透明地自動刷新
- **配額感知輪換** — 遇到 429 速率限制時，該帳號進入指數退避冷卻期，自動切換至下一個可用帳號
- **向後相容** — 現有 API Key 使用者完全不受影響；OAuth 是最低優先級的認證來源

### 認證優先順序

| 優先級 | 來源 | 方式 |
|---|---|---|
| 1 | 設定檔 `api_key` | `config.toml` |
| 2 | `GEMINI_API_KEY` 環境變數 | 環境變數 |
| 3 | `GOOGLE_API_KEY` 環境變數 | 環境變數 |
| 4 | `auth-profiles.json` | 多金鑰設定檔 |
| 5 | **Google OAuth tokens** | `zeroclaw google-auth login` |
| 6 | Gemini CLI tokens | `~/.gemini/oauth_creds.json` |

### 管理帳號

```bash
zeroclaw google-auth list      # 列出所有已登入帳號
zeroclaw google-auth status    # 查看 Token 狀態和過期時間
zeroclaw google-auth remove    # 移除指定帳號
```

## 架構

每個子系統都是一個 **Trait** — 透過設定檔更換實作，零程式碼修改。

| 子系統 | Trait | 內建實作 | 擴展 |
|---|---|---|---|
| **AI 模型** | `Provider` | 22+ 提供者（OpenRouter、Anthropic、OpenAI、Ollama、Gemini 等） | `custom:https://your-api.com` |
| **頻道** | `Channel` | CLI、Telegram、Discord、Slack、iMessage、Matrix、WhatsApp、Webhook | 任何訊息 API |
| **記憶體** | `Memory` | SQLite 混合搜尋（FTS5 + 向量餘弦相似度）、Markdown | 任何持久化後端 |
| **工具** | `Tool` | shell、file_read、file_write、memory_store、memory_recall、browser_open | 任何能力 |
| **可觀測性** | `Observer` | Noop、Log、Multi | Prometheus、OTel |
| **運行時** | `RuntimeAdapter` | Native、Docker（沙箱） | WASM（規劃中） |
| **安全** | `SecurityPolicy` | Gateway 配對、沙箱、白名單、速率限制、加密金鑰 | — |
| **身份** | `IdentityConfig` | OpenClaw（markdown）、AIEOS v1.1（JSON） | 任何身份格式 |
| **隧道** | `Tunnel` | None、Cloudflare、Tailscale、ngrok、Custom | 任何隧道 |
| **技能** | Loader | TOML 清單 + SKILL.md | 社群技能包 |

## 設定

設定檔：`~/.zeroclaw/config.toml`（由 `onboard` 建立）

```toml
api_key = "sk-..."
default_provider = "openrouter"
default_model = "anthropic/claude-sonnet-4-20250514"
default_temperature = 0.7

[memory]
backend = "sqlite"              # "sqlite", "markdown", "none"
auto_save = true
embedding_provider = "openai"   # "openai", "noop"
vector_weight = 0.7
keyword_weight = 0.3

[gateway]
require_pairing = true          # 首次連線需要配對碼
allow_public_bind = false       # 無隧道時拒絕 0.0.0.0

[autonomy]
level = "supervised"            # "readonly", "supervised", "full"
workspace_only = true           # 預設：限定工作區
allowed_commands = ["git", "npm", "cargo", "ls", "cat", "grep"]

[runtime]
kind = "native"                # "native" 或 "docker"

[secrets]
encrypt = true                  # API Key 使用本地金鑰加密

[google_oauth]
enabled = true                  # 為 Gemini 提供者啟用 Google OAuth
# client_id = "..."             # 自訂 OAuth Client ID（可選）
# client_secret = "..."         # 自訂 OAuth Client Secret（可選）
quota_cooldown_base_secs = 60   # 429 後基礎冷卻秒數
quota_cooldown_max_secs = 900   # 最大冷卻秒數（指數退避上限）
```

## 安全

ZeroClaw 在**每一層**都執行安全策略，通過社群安全清單所有項目。

| # | 項目 | 狀態 | 方式 |
|---|---|---|---|
| 1 | **Gateway 不公開暴露** | ✅ | 預設綁定 `127.0.0.1`，無隧道不接受 `0.0.0.0` |
| 2 | **需要配對** | ✅ | 啟動時產生 6 位一次性代碼，透過 `POST /pair` 換取 Bearer Token |
| 3 | **檔案系統限定** | ✅ | 預設 `workspace_only = true`，封鎖 14 個系統目錄 + 4 個敏感 dotfile |
| 4 | **僅透過隧道存取** | ✅ | 無隧道時拒絕公開綁定 |

## 命令

| 命令 | 說明 |
|---|---|
| `onboard` | 快速設定（預設） |
| `onboard --interactive` | 互動式 7 步驟精靈 |
| `onboard --channels-only` | 僅重新設定頻道/白名單 |
| `agent -m "..."` | 單一訊息模式 |
| `agent` | 互動式對話模式 |
| `gateway` | 啟動 Webhook 伺服器（預設：`127.0.0.1:8080`） |
| `daemon` | 啟動長期自主運行模式 |
| `service install/start/stop/status` | 管理背景服務 |
| `doctor` | 診斷系統狀態 |
| `status` | 顯示完整系統狀態 |
| `google-auth login` | 用 Google OAuth 登入（Device Flow） |
| `google-auth list` | 列出所有已登入的 Google 帳號 |
| `google-auth status` | 顯示 Token 狀態和過期時間 |
| `google-auth remove` | 移除 Google 帳號 |

## 開發

```bash
cargo build              # 開發版建置
cargo build --release    # 正式版建置（~3.4MB）
cargo test               # 1,017 測試
cargo clippy             # 程式碼檢查（0 警告）
cargo fmt                # 程式碼格式化
```

## 授權

MIT — 詳見 [LICENSE](LICENSE)

## 貢獻

詳見 [CONTRIBUTING.md](CONTRIBUTING.md)。實作一個 Trait，提交 PR：
- 新 `Provider` → `src/providers/`
- 新 `Channel` → `src/channels/`
- 新 `Tool` → `src/tools/`
- 新 `Memory` → `src/memory/`
- 新 `Tunnel` → `src/tunnel/`
- 新 `Skill` → `~/.zeroclaw/workspace/skills/<name>/`

---

**ZeroClaw** — 零開銷。零妥協。隨處部署。隨意替換。 🦀
