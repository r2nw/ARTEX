# Audit: Outbound hosts & endpoints

Kiểm kê mọi điểm mà binary ARTEX/ScopeWeaver có thể mở kết nối ra ngoài, kèm điều kiện kích hoạt,
dữ liệu gửi kèm và trạng thái bật/tắt mặc định.

- **Trọng tâm**: `llmpool/`, `mcphttp/`, `notify/`, `enrich/`, `report/`
- **Mở rộng**: để trả lời được "mọi host/endpoint binary có thể gọi ra ngoài", tài liệu bao gồm cả
  `selfupdate/` (update), web-search backend trong SDK `norma`, và các kênh traffic tới target.
- **Phiên bản tham chiếu**: `github.com/Autumn-27/norma v0.4.3`, `github.com/projectdiscovery/dnsx v1.2.3`
- **Nhánh**: `claude/outbound-endpoints-audit-trgdj8`

---

## 1. Bảng tổng hợp

Cột "Mặc định" = trạng thái của một cài đặt mới, chưa có người dùng cấu hình gì.

| # | Nhóm | Host / Endpoint | Code | Kích hoạt | Dữ liệu gửi kèm | Mặc định |
|---|------|-----------------|------|-----------|-----------------|----------|
| 1 | LLM provider | `https://api.anthropic.com/v1/messages` (fallback khi `base_url` rỗng) | `agent/provider.go:225`, `norma/llm/anthropic.go:115` | Có LLM profile active + API key; mỗi lượt planner/worker/mainagent/chat, compaction, "Test connection" | Toàn bộ prompt: system prompt, lịch sử hội thoại, tool schema + tool output (có thể chứa HTTP request/response của target), `x-api-key` | ❌ Không có key ⇒ engine idle |
| 2 | LLM provider | `https://api.openai.com/v1/chat/completions` (format `openai`) | `server/server_mgmt.go:2050`, `norma/llm/openai.go:294` | Như trên, khi profile format = `openai` | Như trên, `Authorization: Bearer …` | ❌ |
| 3 | LLM provider | `<base_url>/responses` (format `openai-responses`, default base `https://api.openai.com/v1`) | `agent/provider.go:218`, `norma/llm/openai_responses.go:140` | Như trên | Như trên | ❌ |
| 4 | LLM provider | **Host tuỳ ý** từ `llm_profiles.base_url` (gateway/self-host/OpenRouter/z.ai…) | `agent/provider.go:199` | Người dùng nhập base_url | Như trên + header tuỳ chọn `SessionHeaderKey: <session-id>` | ❌ |
| 5 | LLM provider (search) | `https://html.duckduckgo.com/html/` | `norma/tool/websearch.go:207` | `web_search_enabled=true` + backend `ddgs` **và** agent gọi tool `web_search` | Query string do LLM sinh ra | ❌ (`web_search_enabled` = false) |
| 6 | LLM provider (search) | `https://api.search.brave.com/res/v1/web/search` | `norma/tool/websearch.go:317` | backend `brave-free` + có `BraveKey` | Query + API key | ❌ |
| 7 | LLM provider (search) | `https://api.tavily.com/search` | `norma/tool/websearch.go:376` | backend `tavily` + có `TavilyKey` | Query + API key | ❌ |
| 8 | LLM provider (search) | `<active profile base_url>` (backend `deepseek`, server-side search) | `server/manager.go:609` | backend `deepseek`; dùng lại key/base_url của profile active | Query + prompt + key của profile | ❌ |
| 9 | Update | `https://api.github.com/repos/cskwork/scopeweaver/releases/latest` | `selfupdate/github.go:20` | **Mỗi lần mount UI** (header `UpdateBadge`) → `GET /api/update/check`; cache 30 phút; `force=1` bỏ cache | `Accept: application/vnd.github+json`, `User-Agent: scopeweaver-selfupdate`. Không gửi version/ID/ máy — chỉ là GET ẩn danh | ✅ **BẬT** |
| 10 | Update | `https://github.com/`, `https://objects.githubusercontent.com/`, `https://release-assets.githubusercontent.com/`, `https://raw.githubusercontent.com/` | `selfupdate/github.go:24-30`, `selfupdate/stage.go:150,206` | Chỉ khi người dùng bấm "Update" → `POST /api/update/apply` | GET tải `SHA256SUMS` + `scopeweaver-<ver>-<os>-<arch>.zip` | ❌ (thủ công) |
| 11 | MCP | **URL tuỳ ý** `mcp_servers.url`, transport `http` (Streamable HTTP, POST JSON-RPC) | `mcphttp/client.go:100,428` | MCP row `enabled=true`: discovery lúc startup nếu cache tool rỗng; mỗi lần agent gọi `mcp__<server>__<tool>`; "Test/Discover" trong UI | JSON-RPC `initialize` (`clientInfo: {name:"artex", version:"0.2"}`), `tools/list`, `tools/call` + **arguments do LLM sinh ra**; header từ `mcp_servers.env` (vd. `Authorization`), `Mcp-Session-Id`, `MCP-Protocol-Version: 2025-06-18` | ❌ (không có row HTTP nào enabled) |
| 12 | MCP | **URL tuỳ ý** `mcp_servers.url`, transport `sse` (legacy: `GET /sse` + `POST <endpoint>`) | `mcphttp/client.go:125,504` | Như trên, transport `sse` | Như trên, protocol `2024-11-05`; GET giữ stream dài (không timeout) | ❌ |
| 13 | MCP | MCP ScopeSentry (row seed `name='ScopeSentry'`, `url=NULL`, `X-API-Key=""`) | `db/schema.sql:860`, `server/sync_scopesentry.go` | Người dùng nhập URL + API key, bật row, rồi bấm sync/projects/tasks | `tools/call` lấy subdomain/asset; `X-API-Key` | ❌ (`enabled=false`, url rỗng) |
| 14 | MCP (stdio → mạng) | `npx @playwright/mcp --headless` ⇒ npm registry + Chromium download | `db/db.go:258` | MCP `browser` được bật thủ công | npm/CDN fetch của npx, không phải dữ liệu ARTEX | ❌ (`enabled=false`) |
| 15 | Notification | **DingTalk webhook tuỳ ý** (chính thức: `oapi.dingtalk.com`) | `notify/dingtalk.go:51` | Có channel `dingtalk` enabled **và** có finding event khớp filter | `actionCard`/`markdown`: title, severity, vulnclass, asset, summary, detail URL; `access_token` trong URL + `sign`/`timestamp` HMAC-SHA256 | ❌ (không seed channel) |
| 16 | Notification | **Feishu/Lark webhook tuỳ ý** (chính thức: `open.feishu.cn`) | `notify/feishu.go:58` | Như trên, kind `feishu` | `interactive` card, cùng tập field; `timestamp` + `sign` (HMAC key = `ts\nsecret`) | ❌ |
| 17 | Notification | **WeCom webhook tuỳ ý** (chính thức: `qyapi.weixin.qq.com`) | `notify/wecom.go:50` | Như trên, kind `wecom` | `markdown.content` ≤ 4096 **byte**; key nằm trong URL | ❌ |
| 18 | Notification | `https://api.telegram.org/bot<token>/sendMessage` (hoặc `base_url` tuỳ chỉnh) | `notify/telegram.go:87-95` | Như trên, kind `telegram` | `chat_id`, `text` (HTML ≤ 4096 ký tự), `parse_mode`; bot token nằm trong path | ❌ |
| 19 | Notification | **URL + method + header tuỳ ý** (webhook generic: Slack/Mattermost/Discord/receiver nội bộ) | `notify/webhook.go:131` | Như trên, kind `webhook`; method GET/POST/PUT/PATCH | Body JSON theo template (default: `finding_id`, `name`, `vulnclass`, `severity`, `summary`, `assets`, `detail_url`); header tuỳ ý (thường chứa token) | ❌ |
| 20 | Notification | **SMTP host:port tuỳ ý** (TCP, không phải HTTP) | `notify/email.go:128` | Như trên, kind `email` | `From`/`To`/`Subject` + body HTML base64 (toàn bộ digest, không cắt); `PLAIN` auth user/password | ❌ |
| 21 | Notification | Mọi host ở #15–20 cũng bị gọi qua nút **"Test send"** | `server/notify_api.go:428` | Người dùng bấm test | Message mẫu, không phải finding thật | ❌ (thủ công) |
| 22 | Enrich (DNS) | `1.1.1.1:53`, `1.0.0.1:53`, `8.8.8.8:53`, `8.8.4.4:53`, `9.9.9.9:53`, `149.112.112.112:53`, `208.67.222.222:53`, `208.67.220.220:53` — UDP | `enrich/enrich.go:68` + `dnsx.DefaultResolvers` | Gọi `Engine.ResolveDomain()` → **hiện không có call site nào** (xem §5) | Query A/AAAA/CNAME cho FQDN của target | ⚠️ Engine khởi tạo mặc định, nhưng **không phát traffic** |
| 23 | Enrich (HTTP) | **Host của target** (`GET <site url>`), đi qua recording proxy nếu capture đang bật | `enrich/enrich.go:230` | Gọi `Engine.ProbeSite()` → **không có call site nào** | `GET` + `User-Agent: artex-enrich/1.0`; `InsecureSkipVerify: true`; đọc ≤ 1 MiB body | ⚠️ Như trên |
| 24 | Target traffic | **Host tuỳ ý** do agent chọn: tool `Bash` (curl/nmap/sqlmap…), `WebFetch`, browser MCP, recording proxy | `agent/worker.go:205`, `intercept/`, `traffic/` | Chạy task pentest | Payload do LLM sinh ra; `HTTP_PROXY`/`HTTPS_PROXY` trỏ về recording proxy nội bộ | ✅ Theo task (đây là chức năng chính) |
| 25 | **Telemetry** | — | — | — | — | **Không tồn tại** (xem §6) |

---

## 2. `llmpool/` — không tự mở socket

`llmpool` là **decorator** trên `llm.Provider`, không import `net/http`:

```
$ grep -rn "net/http\|http\." llmpool/*.go   # (loại test) → không có kết quả
```

- `Pool.Stream` / `Pool.Complete` (`llmpool/pool.go:82,130`) chỉ gọi `m.Prov.Stream/Complete` của từng
  `Member`. Endpoint thật nằm ở `Member.Prov`, được server build từ `llm_profiles` qua
  `agent.ConfigFrom` → `Config.NewProvider` (`agent/provider.go:199,257`).
- **Hệ quả cho audit**: một request có thể lần lượt đi tới **nhiều host khác nhau** trong một lượt
  LLM. Chain failover = profile active (Rank `RankActive`) rồi tới các profile khác theo `priority DESC`
  (`llmpool/pool.go:40,168`). Mỗi lần failover gửi **lại nguyên prompt** cho host tiếp theo.
- Điều kiện failover (`shouldFailover`, `pool.go:231`): status `401/402/403/404/408/429`, mọi `5xx`,
  hoặc lỗi transport (status 0). **Không** failover khi context cancel hoặc `400`.
- Chặn gửi lặp: chỉ failover **trước khi** event đầu tiên tới caller (`pool.go:90`) — mid-stream lỗi
  thì không gửi lại sang host khác.
- Circuit breaker (`llmpool/health.go`): host lỗi bị skip 1 phút / 5 phút / 30 phút (ladder), hard
  failure (401/402/403/404) mở ngay lần đầu. Đây là cơ chế **giảm** số lần gọi ra ngoài.
- Lọc theo context window (`pool.go:175`): profile có window nhỏ hơn request bị bỏ qua — nếu tất cả bị
  loại, vẫn probe head chain (`pool.go:181`).

### Default base URL khi `base_url` rỗng

| Format profile | Base mặc định | Path SDK append |
|---|---|---|
| `anthropic` (default) | `https://api.anthropic.com` (hoặc env `ANTHROPIC_BASE_URL`) | `/v1/messages` |
| `openai` | `https://api.openai.com/v1` (hoặc env `OPENAI_BASE_URL`) | `/chat/completions` |
| `openai-responses` | `https://api.openai.com/v1` | `/responses` |

Nguồn: `agent/provider.go:211-228`, `norma/llm/provider.go:184,195,203`.

### Proxy

`Config.Proxy` rỗng ⇒ `transport.Proxy = nil` — **cố tình không** fallback sang `HTTP_PROXY`/`HTTPS_PROXY`
(`agent/provider.go:412`). Khác với default của SDK norma. Chỉ nhận scheme `http`/`https`/`socks5`.

### Dữ liệu gửi kèm (quan trọng nhất về mặt rủi ro)

Request body do `norma` build, chứa toàn bộ:
- system prompt + lịch sử hội thoại (sau compaction),
- schema của mọi tool đang bật (gồm cả MCP tool),
- **tool result** — tức là HTTP request/response thô của target, nội dung file đọc được, output Bash.

Header: `x-api-key` (anthropic) hoặc `authorization: Bearer` (openai), `anthropic-version: 2023-06-01`,
và tuỳ chọn `<SessionHeaderKey>: <session-id>` (`agent/provider.go:351`) cho gateway cần sticky routing.
`quotaAwareTransport` cũng chụp request/response body vào `llmrec.Capture` khi bật ghi LLM — chỉ lưu
nội bộ (DB), không gửi đi đâu.

---

## 3. `mcphttp/` — JSON-RPC ra host do người dùng cấu hình

Không có host hard-code. Đích đến = `mcp_servers.url`.

| Thuộc tính | Streamable HTTP (`New`) | Legacy SSE (`NewSSE`) |
|---|---|---|
| Entry | `mcphttp/client.go:100` | `mcphttp/client.go:125` |
| Request | `POST <url>` JSON-RPC | `GET <url>` (stream) + `POST <endpoint do server công bố>` |
| Protocol version | `2025-06-18` | `2024-11-05` |
| Timeout | 120s (`client.go:105`) | **Không timeout** (stream dài, `client.go:130`) |
| Header gửi | `Content-Type`, `Accept: application/json, text/event-stream`, `MCP-Protocol-Version`, `Mcp-Session-Id`, + toàn bộ `mcp_servers.env` | `Accept`, + `env` |
| Đóng session | `DELETE <url>` + `Mcp-Session-Id` (`client.go:378`) | cancel stream, không gọi mạng |

**Chuỗi RPC gửi ra ngoài**

1. `initialize` — `protocolVersion`, `capabilities: {}`, `clientInfo: {name:"artex", version:"0.2"}`
   (`client.go:248`). Đây là thông tin duy nhất mô tả client; không có version build, hostname, hay ID máy.
2. `notifications/initialized`
3. `tools/list`
4. `tools/call` — `{name, arguments}`. **`arguments` do LLM sinh ra**, nên có thể chứa bất cứ gì model
   quyết định đưa vào (domain target, payload, nội dung trích từ traffic).

**Điều kiện kích hoạt**

- Startup: `discoverEmptyMCPsOnStartup` (`server/mcpdiscover.go:71`) kết nối mọi MCP `enabled=true` còn
  cache tool rỗng, tuần tự, async, best-effort. Mặc định không có row HTTP/SSE nào enabled ⇒ không kết nối.
- Runtime: mỗi tool call của agent (có gate `permission.AskUser`, `client.go:293`) — trừ
  `Client.Call` (`client.go:331`) dùng cho batch job backend, **bỏ qua lớp permission**.
- UI: "Test/Discover" một MCP row; các endpoint `/api/sync/scopesentry/*` (thủ công, không có cron).

**Lưu ý bảo mật**: `insecure=true` ⇒ `InsecureSkipVerify` (`client.go:107,132`). Mặc định DB là `false`
(`db/schema.sql:842`). Không có guard SSRF nào ở `mcphttp` — URL loopback/metadata vẫn gọi được (khác
hẳn `notify`, xem §4).

---

## 4. `notify/` — 6 kênh, mọi đích đến do người dùng nhập

Không có host hard-code, **trừ** default base của Telegram: `https://api.telegram.org`
(`notify/telegram.go:89`). Các host chính thức ở bảng §1 chỉ mang tính tham khảo.

### Điều kiện kích hoạt (xếp theo thứ tự cổng)

1. Setting `notify_enabled` — **mặc định `true`** (`server/notifier.go:498`), là công tắc bảo trì khẩn cấp.
2. Dispatcher `Notifier.Run` chạy ngay từ `server.New`, tick **3 giây** (`notifier.go:32`).
3. Phải có row trong `notification_channels` với `enabled=true`. **Không channel nào được seed** —
   đây là lý do thực sự khiến mặc định không có traffic.
4. Phải có `notification_events` (finding created / finding status changed) vượt filter của channel
   (`notify/filter.go:12`: `min_severity`, `task_ids`, `asset_ids`, `vulnclass_include/exclude`,
   `on_status_change`). Lưu ý: filter JSONB lỗi cú pháp ⇒ fallback về zero-value = **không filter**,
   tức gửi tất cả (`ParseFilter`, `filter.go:30`).
5. Token bucket per-channel: `DefaultRatePerMin` = DingTalk/WeCom 20, Telegram 20, Feishu 100,
   Email 60, webhook 0 (không giới hạn).
6. Mỗi tick tối đa 5 lần gửi/channel, timeout 30s/lần, lease 3 phút (`notifier.go:46-62`).
7. Retry: tối đa 3 lần (`db.MaxNotifyAttempts`), backoff 1s/5s/30s; `PermanentError` không retry.

Chế độ realtime (gửi từng finding) hoặc digest (gom theo `notify_digest_interval_min`, default 30 phút).

### Dữ liệu gửi kèm — giới hạn rõ ràng

Nguồn duy nhất là `notify.Snapshot` (`notify/event.go:10`):

```
kind, finding_id, task_id, vulnclass, name, severity, summary,
asset_ids, from_status, to_status
```

Khi render thành `Item` server bổ sung `Assets` (tên domain/IP) và `DetailURL`
(`<notify_public_base_url>/function/findings/detail?id=<n>`, rỗng nếu chưa set setting).

**Không gửi**: evidence, PoC, raw request/response, nội dung file. `report.findingView` có `PoC` nhưng
chỉ dùng cho báo cáo local — không đi vào notify.

Giới hạn kích thước: WeCom 4096 **byte**, Telegram 4096 **ký tự**, DingTalk 20000, email không cắt.
Phần bị cắt được giữ lại cho batch sau (`Channel.Send` trả `kept`).

### Guard SSRF (chỉ có ở package này)

- `blockInternalDial` (`notify/http.go:51`) là `Dialer.Control` — chặn **tại thời điểm dial**, nên
  chống được DNS rebinding và redirect. Chặn: loopback, link-local (gồm `169.254.169.254` metadata),
  unspecified, multicast. **Cho phép** RFC1918 (để Mattermost/SMTP nội bộ dùng được).
- Opt-out: `ARTEX_NOTIFY_ALLOW_LOCAL=1` (`notify/http.go:26`).
- `validateHTTPURL` (`notify/dingtalk.go:129`) chặn thêm lúc save: chỉ `http`/`https`.
- Redirect: tối đa 5 hop, **chặn cross-host redirect** (`notify/http.go:89`) vì credential nằm trong
  URL/query.
- HTTP client của notify **không** dùng `GlobalProxy` của server (`notify/http.go:81`) — chủ ý tách
  khỏi mạng target.
- SMTP: cùng guard `blockInternalDial` (`notify/email.go:134`); `smtp.PlainAuth` tự từ chối gửi
  credential trên kết nối chưa mã hoá; STARTTLS tự upgrade nếu server hỗ trợ; TLS min 1.2.
- Redact: `redactRequestTarget` / `redactTransportError` (`notify/http.go:166,176`) chỉ để lại
  `scheme://host/…` trong `last_error` và delivery history, vì token nằm trong path/query.

---

## 5. `enrich/` — có khả năng gọi ra ngoài, nhưng hiện không có call site

Đây là phát hiện đáng chú ý nhất của lần audit này.

**Khả năng**:
- DNS: `dnsx.New` với `BaseResolvers: dnsx.DefaultResolvers` (`enrich/enrich.go:68`) ⇒ 8 resolver công
  khai của Cloudflare / Google / Quad9 / OpenDNS qua **UDP/53** (xem #22). Query A, AAAA, CNAME;
  timeout 4s, 3 retry.
- HTTP: `GET <site url>` với `User-Agent: artex-enrich/1.0`, `InsecureSkipVerify: true`,
  `DisableKeepAlives`, timeout 12s, đọc ≤ 1 MiB, không follow redirect (`ErrUseLastResponse`).
  Đi qua recording proxy nếu `Manager.ProxyAddr()` khác rỗng (resolve per-request nên toggle capture
  có tác dụng ngay).

**Thực tế**: `Engine` được tạo vô điều kiện lúc startup (`server/manager.go:475`, 4 worker goroutine) và
inject vào mỗi worker (`agent/worker.go:359` → `ToolSet.SetEnrich`), nhưng field `ToolSet.enrich`
**không được dereference ở bất kỳ đâu**:

```
$ grep -rn "ResolveDomain\|ProbeSite" --include="*.go" .
./agent/tools.go:137          ResolveDomain(id int64, host string)   # khai báo interface
./agent/tools.go:138          ProbeSite(id int64, url string)        # khai báo interface
./enrich/enrich.go:120,123    # định nghĩa method
# → không có call site nào
```

`dnsx.New` không phát packet lúc khởi tạo, nên **hiện tại enrich không sinh traffic ra ngoài**. Nhưng
code đường ra vẫn còn nguyên, và doc comment của package vẫn nói "HTTP probing is gated by RoE (§5.2)"
— **gate RoE đó không tồn tại trong code**. Nếu sau này nối call site vào `insert_assets`, traffic sẽ
đi ra ngay mà không qua kiểm tra scope nào, và DNS được đánh dấu "ungated" (`enrich.go:118`) sẽ leak
tên domain của khách hàng tới resolver của Cloudflare/Google/Quad9/OpenDNS.

Cooldown 5 phút per `(kind, id)`, queue 1024, đầy thì drop (`enrich.go:56,131`).

---

## 6. `report/` — không có outbound. `telemetry` — không tồn tại

**`report/`**: thuần render local.

```
$ grep -rn "net/http\|http\.\|url\.\|exec\.\|smtp" report/*.go   # (loại test) → không có kết quả
```

- `report.Markdown` (`report/report.go:48`) build string Markdown từ `db.Node`.
- `report.AssetsCSV` (`report/assets.go:96`) build CSV (có UTF-8 BOM cho Excel).
- `report/findings.go`, `report/locale*`: format + i18n.

Output trả về qua HTTP response của ARTEX cho browser — **không** upload đi đâu. Đây cũng là package duy
nhất trong 5 package được yêu cầu mà có thể khẳng định tuyệt đối "zero outbound".

**Telemetry**: nhóm này **rỗng**. Không có code gửi usage/crash/analytics:

```
$ grep -rni "telemetry|analytics|sentry|posthog|umami|phone.home|usage.report" --include="*.go" .
# chỉ khớp chuỗi "ScopeSentry" (tên sản phẩm ASM của bên thứ ba) — không phải Sentry SDK
$ grep -rni "analytics|gtag|googletagmanager|sentry|posthog" web/src web/package.json
# chỉ khớp "ScopeSentry"
```

Điểm gần nhất với telemetry là update check (#9) — nhưng đó là `GET` ẩn danh tới GitHub, không gửi
version hiện tại, OS, arch hay bất kỳ identifier nào lên server; việc so sánh version diễn ra local
(`selfupdate.CompareVersions`).

---

## 7. Cái gì bật mặc định

### Bật mặc định (có traffic trên cài đặt mới, chưa cấu hình gì)

| Endpoint | Tần suất | Ghi chú |
|---|---|---|
| `https://api.github.com/repos/cskwork/scopeweaver/releases/latest` | Mỗi lần mount UI, cache 30 phút | **Outbound duy nhất tự phát** của một cài đặt mới. Trình duyệt cũng tự gọi `api.github.com` (CORS cho phép) — nhưng backend mới là nguồn authoritative (`server/update.go:214`) |

### Dispatcher chạy mặc định nhưng không có đích

| Thành phần | Mặc định | Vì sao không có traffic |
|---|---|---|
| `Notifier.Run` (tick 3s) | `notify_enabled=true` | Không channel nào được seed ⇒ `ListNotificationChannels` rỗng |
| `enrich.Engine` (4 worker) | Luôn khởi tạo | Không có call site gọi `ResolveDomain`/`ProbeSite` (§5) |
| `discoverEmptyMCPsOnStartup` | Luôn chạy | Chỉ 2 row seed: `browser` (stdio, `enabled=false`), `ScopeSentry` (http, `enabled=false`, `url=NULL`) |

### Tắt mặc định (cần cấu hình/hành động)

| Endpoint / nhóm | Cần gì để bật |
|---|---|
| LLM provider (#1–4) | Tạo LLM profile + API key (hoặc env `ANTHROPIC_API_KEY`/`OPENAI_API_KEY`). Không có key ⇒ `FromEnv` trả `ok=false`, engine idle |
| Web search (#5–8) | `web_search_enabled=true` (default `false`, `server/manager.go:449`) + backend. `ddgs` không cần key; `brave-free`/`tavily` thiếu key thì tool bị tắt hẳn |
| Update download (#10) | Bấm "Update" trong Settings. Build dev (version không so sánh được) bị chặn hẳn |
| MCP HTTP/SSE (#11–13) | Tạo row `mcp_servers` transport `http`/`sse` + `enabled=true` |
| MCP browser (#14) | Bật row `browser` |
| 6 kênh notify (#15–20) | Tạo channel + nhập webhook/token/SMTP |
| Traffic tới target (#24) | Chạy task (đây là chức năng chính của sản phẩm) |

---

## 8. Ghi chú về hardening đã có và điểm cần biết

**Đã có**
- `selfupdate`: allowlist 5 host GitHub (`selfupdate/github.go:24`) + bắt buộc HTTPS, kiểm tra **mọi**
  redirect hop qua `CheckRedirect` (`github.go:71`), transport riêng không bao giờ bật
  `InsecureSkipVerify`, và verify SHA256 từ `SHA256SUMS` của release (hai lớp gate). `Repo` là hằng số
  — cố tình không cho cấu hình để tránh biến setting thành đường RCE (`selfupdate/github.go:14`).
- `notify`: guard SSRF tại dial-time, chặn cross-host redirect, redact credential trong log/history,
  không dùng proxy target.
- LLM: không fallback env proxy; `llmpool` circuit breaker giảm số request tới host đã lỗi.

**Cần biết**
1. `mcphttp` **không có** guard SSRF — URL MCP trỏ loopback/`169.254.169.254` vẫn được gọi. Khác với
   `notify`. Rủi ro thấp hơn (chỉ admin cấu hình được), nhưng không đối xứng.
2. `enrich`: dead code có đường ra ngoài + comment nói có RoE gate mà code không có. Nếu nối lại call
   site, DNS của target đi tới 8 resolver công khai, và HTTP probe chạy với `InsecureSkipVerify` không
   check scope.
3. `enrich` HTTP probe và LLM provider dùng `InsecureSkipVerify: true` (có lý do: proxy MITM re-sign,
   target self-signed) — chỉ `selfupdate` và `notify` giữ verify đầy đủ.
4. Credential của notify nằm trong URL (DingTalk `access_token`, WeCom key, Telegram bot token,
   Feishu hook path) ⇒ mọi log/error phải redact; code đã làm, nhưng bất kỳ adapter mới cũng phải
   tuân theo `SecretKeys()`/`DestinationKeys()`.
5. Payload lớn nhất gửi ra ngoài là request LLM: chứa tool output, tức traffic thô của target. Đây là
   kênh rò rỉ dữ liệu khách hàng rộng nhất và chỉ bị giới hạn bởi việc chọn LLM provider / self-host.

**Ngoài phạm vi binary** (script, không chạy trong runtime): `install.sh` tải `https://get.docker.com`;
`Dockerfile` tải `https://deb.nodesource.com/setup_20.x`.
