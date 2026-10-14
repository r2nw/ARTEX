# Audit: `traffic/` và MITM proxy (port 8788)

| | |
|---|---|
| Phạm vi | Gói `traffic/`, phần MITM proxy nhúng, CA root, cấu hình bind/auth |
| Commit | `d999b19` (branch `claude/audit-mitm-proxy-agqqvp`) |
| Ngày | 2026-10-14 |
| Thư viện MITM | `github.com/lqqyt2423/go-mitmproxy v1.9.2` (`go.mod:11`) |
| Phương pháp | Đọc code + chạy PoC cục bộ (xem [Phụ lục A](#phu-luc-a-poc-da-chay)) |

---

## 1. Tóm tắt điều hành

Proxy ghi traffic là một **forward proxy MITM không có bất kỳ cơ chế xác thực nào**, không có allowlist host/port, và nó **ghi lại toàn bộ request/response ở dạng plaintext** vào kho bằng chứng mà agent LLM đọc. Mặc định bind `127.0.0.1:8788` nên rủi ro được khoanh ở loopback — nhưng mặc định này bị phá vỡ ở nhiều đường triển khai thực tế (Dockerfile `CMD`, ví dụ trong README, compose bench dùng `network_mode: host`).

Nếu port 8788 lộ ra ngoài loopback, kẻ tấn công **không cần credential** sẽ có: open relay HTTP/HTTPS, **tunnel TCP tuỳ ý qua CONNECT** (pivot vào mạng nội bộ, kể cả `127.0.0.1`), khả năng **bơm dữ liệu vào kho bằng chứng** mà agent LLM sẽ đọc (indirect prompt injection), và DoS ổ đĩa. Chi tiết ở [mục 6](#6-ket-luan-neu-port-8788-lo-ra-ngoai).

Vấn đề thứ hai, độc lập với chuyện lộ port: **private key của CA root được lưu quyền `0644`**, nằm trong workspace mà agent và file-manager API đọc/tải được, và được tái dùng vĩnh viễn (không rotate, hạn 3 năm).

---

## 2. Kiến trúc `traffic/`

Đường đi của một exchange:

```
worker/agent (bash, curl, playwright...)
   │  HTTP_PROXY / HTTPS_PROXY = http://127.0.0.1:8788
   │  SSL_CERT_FILE / NODE_EXTRA_CA_CERTS = data/traffic/_ca/mitmproxy-ca-cert.pem
   ▼
go-mitmproxy entry (:8788)  ── không auth ──┐
   │ CONNECT → MITM (re-sign) hoặc tunnel thẳng
   ▼
addon `sink` → Traffic.record()              │ SslInsecure: true
   │                                         │ (không verify cert upstream)
   ├─ data/traffic/_index/index.sqlite  (metadata + body + FTS5 trigram)
   └─ data/traffic/_blobs/sha256/..    (body > 256 KiB)
   ▼
upstream: dial trực tiếp, hoặc qua global egress proxy nếu có cấu hình
```

Các điểm neo trong code:

| Thành phần | Vị trí |
|---|---|
| Khởi tạo thư mục + mở proxy | `traffic/traffic.go:177-233` |
| Tạo `mproxy.Proxy` (`SslInsecure: true`, `CaRootPath`) | `traffic/traffic.go:205-213` |
| Chọn upstream (direct hoặc global proxy) | `traffic/traffic.go:222` |
| Quy tắc intercept (fail-open) | `traffic/traffic.go:226-229` |
| Addon ghi dữ liệu | `traffic/traffic.go:388-398`, `record()` tại `:437-511` |
| Tách body lớn ra blob | `traffic/traffic.go:527-565` |
| Đổi sang passthrough khi MITM lỗi | `traffic/traffic.go:409-432` |
| Wiring trong server | `server/manager.go:410-441` |
| Env tiêm cho worker | `agent/worker.go:205-225` |

### 2.1. Nội dung được ghi: plaintext, không redaction

`record()` (`traffic/traffic.go:437-511`) ghi nguyên văn:

- request line + **toàn bộ header** (`requestHeaderLines`, `traffic/traffic.go:654-669`) — bao gồm `Authorization`, `Cookie`, `X-Api-Key`;
- response status + toàn bộ header, kèm `Set-Cookie`;
- body request/response: ≤ 256 KiB thì nằm inline trong SQLite, lớn hơn thì ghi ra `_blobs` **quyền `0644`** (`traffic/traffic.go:553`), giữ lại 8 KiB preview;
- toàn bộ text trên được nạp vào FTS5 trigram để search substring (`traffic/traffic.go:498-506`).

Không có bất kỳ bước lọc/masking nào — điều này là **thiết kế có ý thức** (comment đầu file: *"Full capture, plaintext (no redaction)"*), phù hợp với mục đích pentest, nhưng nó quyết định mức thiệt hại khi port bị lộ hoặc khi file dữ liệu bị đọc.

### 2.2. Không có allowlist scope

`SetShouldInterceptRule` (`traffic/traffic.go:226-229`) chỉ quyết định **MITM hay tunnel thẳng**, chứ không quyết định cho đi hay chặn: mọi host đều được forward. Không có khái niệm "chỉ proxy cho target trong scope". Tức proxy này về bản chất là open forward proxy, chỉ được bảo vệ bằng địa chỉ bind.

### 2.3. Fail-open passthrough có thể bị lợi dụng để tắt ghi log

`maybePassthrough` (`traffic/traffic.go:409-420`) ghi host vào `t.pass` khi gặp lỗi mà chuỗi lỗi chứa `head request` / `http2` / `protocol error` / `malformed` (`:424-432`). Từ đó về sau, **mọi** kết nối tới host đó được tunnel thẳng, không ghi lại gì, cho tới khi process restart (`t.pass` chỉ nằm trong RAM, không có TTL, không có cách xoá qua API).

Hệ quả: ai gửi được request qua proxy (hoặc một target biết trả lời sai lệch protocol) có thể làm **mất bằng chứng** cho một host — kể cả host target đang được audit. Chưa viết PoC cho đường này, nên đánh giá là *plausible*, không phải *confirmed*.

---

## 3. CA root: sinh ở đâu, lưu ở đâu, quyền gì

### 3.1. Sinh ở đâu

ARTEX không tự sinh CA. Nó truyền `CaRootPath` cho go-mitmproxy (`traffic/traffic.go:205-209`), thư viện gọi `cert.NewSelfSignCA(path)` và **load-or-create**:

- `cert/self_sign_ca.go:102-128` — nếu đọc được `mitmproxy-ca.pem` thì dùng lại, chỉ khi không tồn tại mới tạo mới;
- `cert/self_sign_ca.go:44-84` — CA mới: **RSA 2048**, self-signed, `CN=mitmproxy, O=mitmproxy`, `IsCA: true`, hiệu lực **3 năm** (`NotBefore` lùi 48h), serial = `UnixNano()/100000`, `ExtKeyUsage` rất rộng (bao gồm cả code signing);
- cert lá cho từng host: `DummyCert` (`cert/self_sign_ca.go:333-365`), RSA key **dùng chung với CA**, hiệu lực 1 năm, 1 SAN duy nhất, cache LRU 100.

→ **Tái dùng, không sinh lại mỗi lần.** Chỉ sinh mới khi `mitmproxy-ca.pem` biến mất (data dir mới, container không mount volume, hoặc user xoá file). Không có cơ chế rotate, không CRL, không cảnh báo khi CA gần hết hạn.

Lưu ý phụ: subject `CN=mitmproxy, O=mitmproxy` là **giống hệt nhau trên mọi cài đặt** — không phân biệt được CA của instance nào khi đã trust nhiều cái.

### 3.2. Lưu ở đâu

Thư mục `_ca` được ARTEX tạo trước với quyền `0755` (`traffic/traffic.go:178-182`), đường dẫn `<data>/traffic/_ca`:

| Triển khai | Đường dẫn |
|---|---|
| Binary release | `<thư mục chứa binary>/data/traffic/_ca/` (`cmd/artex/main.go:55`, `config/config.go:44-54`) |
| `go run ./cmd/artex` / `dev.sh` | `./data/traffic/_ca/` (CWD) |
| Docker | `/app/data/traffic/_ca/` → bind-mount ra `./data` trên host (`docker-compose.yml:37`) |

Ba file (`cert/self_sign_ca.go:167-178`):

| File | Nội dung |
|---|---|
| `mitmproxy-ca.pem` | **PRIVATE KEY (PKCS#8) + CERTIFICATE** — đây là file nhạy cảm |
| `mitmproxy-ca-cert.pem` | Chỉ cert, đây là file các client trust (`traffic/traffic.go:355-357`) |
| `mitmproxy-ca-cert.cer` | Bản copy cho Windows |

### 3.3. Quyền file

Thư viện ghi bằng `os.Create` (`cert/self_sign_ca.go:270-300`) → `0666 & ~umask`, **không có `chmod` theo sau**, không có `O_EXCL`. Với umask mặc định `0022`:

```
mitmproxy-ca.pem       mode=-rw-r--r--   (private key, world-readable)
mitmproxy-ca-cert.pem  mode=-rw-r--r--
mitmproxy-ca-cert.cer  mode=-rw-r--r--
_ca/ (dir)             mode=drwxr-xr-x
```

Kết quả này được xác nhận bằng PoC (xem [Phụ lục A](#phu-luc-a-poc-da-chay)) — vừa bằng cách gọi trực tiếp `cert.NewSelfSignCA`, vừa qua `traffic.Open` + `Start`.

Đối chiếu: những secret khác trong cùng codebase *có* được xử lý đúng — JWT signing key ghi `0600` và còn được di chuyển ra **ngoài** workspace để không bị file-manager tải về (`server/auth.go:40-76`). CA private key thì không được đối xử như vậy:

- quyền `0644` → mọi user local đọc được;
- nằm **trong** `s.m.dir` (data dir), tức nằm trong workspace mà file-manager API `GET /api/workspace/download` phục vụ (`server/workspace.go:30-38`, routes tại `server/server.go:716-722`) — có auth, nhưng không có exclusion nào cho `_ca`;
- cũng nằm trong workspace mà agent LLM chạy bash/đọc file, và agent đã được tiêm sẵn đường dẫn `_ca` qua `SSL_CERT_FILE`/`NODE_EXTRA_CA_CERTS` (`agent/worker.go:215-223`) → một câu lệnh do LLM sinh ra có thể đọc và đẩy key đi.

Ai có file này thì ký được cert hợp lệ cho **bất kỳ** domain nào, và cert đó được tin trên mọi máy đã trust CA (máy pentester, container worker, browser Playwright). CA hạn 3 năm, không rotate → thiệt hại kéo dài.

---

## 4. Bind interface mặc định

| Nơi khai báo | Giá trị | Interface thực tế |
|---|---|---|
| `cmd/artex/main.go:56` (mặc định flag) | `127.0.0.1:8788` | **Chỉ loopback** ✅ |
| `dev.sh:12` | `127.0.0.1:8788` | Chỉ loopback ✅ |
| `Dockerfile:46` (`CMD`) | `:8788` | **0.0.0.0 trong container** ⚠️ |
| `docker-compose.yml:35` | publish `127.0.0.1:8788:8788` | Chỉ loopback host ✅ |
| `docker-compose.bench.yml:14` | `network_mode: host` + CMD của `Dockerfile.bench` | **mọi interface của host** ⚠️ (file bench không có trong repo nên không xác nhận được flag) |
| `README.md:338` ("Common flags") | `./start.sh -addr :8787 -proxy :8788` | **0.0.0.0** ⚠️ — ví dụ trong tài liệu dạy sai |

Mặc định loopback là kết quả của một lần sửa trước đó (`CHANGELOG.md:199`: *"Traffic capture proxy now binds only to 127.0.0.1 by default (#129, #130), avoiding an open proxy on other interfaces"*), và `traffic/proxy_test.go:62-79` còn ghi rõ `:8788` là "legacy default". Nhưng phần còn lại của repo chưa theo kịp:

- `Dockerfile` CMD vẫn bind all-interfaces; an toàn hiện tại **chỉ nhờ** port mapping trong `docker-compose.yml`. Chạy `docker run -p 8788:8788 scopeweaver:local` hay `--network host` là mất lớp bảo vệ duy nhất.
- README dạy người dùng gõ `-proxy :8788`.
- Không có **cảnh báo log** nào khi proxy bind ra ngoài loopback. `ProxyAddr()` (`traffic/traffic.go:306-311`) chỉ dịch `:8788`/`0.0.0.0:8788` thành URL cho agent dùng, không hề phản đối.

### 4.1. Listener chạy kể cả khi tắt "traffic capture" trên UI

`server/manager.go:410-441`: hễ `proxyAddr != ""` là `traffic.Open` + `tr.Start()` được gọi, **không phụ thuộc** vào setting `settingTrafficCapture`. Toggle đó (`server/manager.go:484-505`) chỉ quyết định: có trỏ agent vào proxy hay không, có expose tool `traffic_*` hay không, và có inject proxy vào browser MCP hay không. Nó **không** đóng listener và **không** tắt `record()`.

→ Người vận hành tắt capture trên UI vẫn còn một MITM proxy mở ở 8788, và mọi thứ người ngoài đẩy qua đó vẫn được ghi đầy đủ vào `index.sqlite`.

---

## 5. Xác thực: không có

Không có. `authProxy` của go-mitmproxy là nil trong suốt codebase:

- thư viện *có* hỗ trợ: `Proxy.SetAuthProxy` (`proxy/proxy.go:131-133`), kèm ví dụ Basic auth tại `examples/proxy-auth/main.go`;
- `entry.ServeHTTP` chỉ kiểm tra khi hook được set: `if e.proxy.authProxy != nil { ... 407 ... }` (`proxy/entry.go:186-194`);
- ARTEX **chưa bao giờ gọi** `SetAuthProxy` — grep toàn repo chỉ ra `SetUpstreamProxy` và `SetShouldInterceptRule`.

Ngoài ra cũng không có: IP allowlist, rate limit, giới hạn host/port đích, giới hạn số byte ghi. Đối chiếu với API 8787 — nơi đó có JWT + bcrypt password và `requireAuth` (`server/auth.go`) — thì 8788 hoàn toàn trống.

---

## 6. Kết luận: nếu port 8788 lộ ra ngoài

Giả định: kẻ tấn công tới được TCP 8788 (host bind `:8788`, `docker run -p`, `network_mode: host`, port-forward, hoặc chỉ đơn giản là cùng LAN/VPN với máy pentester). **Không cần credential, không cần đã trust CA.**

### 6.1. Pivot TCP tuỳ ý qua CONNECT — tác động cao nhất

`handleConnect` (`proxy/entry.go:220-253`) chấp nhận mọi `CONNECT host:port`. Nếu 3 byte đầu không phải TLS và không phải WebSocket, `httpsDialLazyAttack` rơi xuống `transfer()` — **relay TCP thô hai chiều** (`proxy/entry.go:426-434`). Đã xác nhận bằng PoC: `CONNECT 127.0.0.1:<port>` → `200 Connection Established` → trao đổi byte thô thành công.

Nghĩa là 8788 là một **SOCKS-tương-đương không mật khẩu**:

- vào `127.0.0.1` của máy chủ ARTEX: API 8787 (bypass mọi firewall chặn 8787 từ ngoài), PostgreSQL 5432, Redis/SSH/bất cứ thứ gì đang listen loopback;
- vào mọi host trong mạng nội bộ mà máy ARTEX với tới — máy pentester thường được cấp quyền mạng rộng hơn bình thường, nên đây là bàn đạp đặc biệt giá trị;
- không có giới hạn port → không chỉ HTTP.

### 6.2. Open relay + mạo danh nguồn (attribution laundering)

Request HTTP thường cũng được forward vô điều kiện (PoC: `GET` qua proxy tới target → `200`, không credential). Thêm vào đó, mọi traffic của kẻ tấn công **đi qua global egress proxy** của người vận hành nếu đã cấu hình (`traffic/traffic.go:222`, `SetUpstreamProxy` tại `:318-329`, bao gồm cả `user:pass` đã lưu).

Với một hệ thống pentest, đây là rủi ro pháp lý trực tiếp: traffic tấn công bên thứ ba **xuất phát từ IP/identity được authorize của pentester**, và còn được ghi vào chính evidence store của họ như thể do bài test sinh ra.

### 6.3. Bơm bằng chứng → indirect prompt injection vào agent có bash

`sink.Response` → `record()` chạy cho **mọi** exchange đi qua proxy, bất kể do ai gửi, và `t.pass`/scope không lọc gì. Kẻ tấn công vì vậy ghi được nội dung tuỳ ý vào `exchanges` + FTS index, với `host` do chính hắn chọn (ví dụ đúng host của target đang audit).

Agent LLM được chỉ thị rõ ràng là phải đọc traffic đã ghi — `workerTrafficBlock` (`agent/worker.go:238-243`): *"Check recorded traffic first; do not curl the same URL again"* — qua `traffic_search` / `traffic_get` / `traffic_blob`. `body_contains` là trigram substring search, nên nội dung chèn vào rất dễ được kéo lên.

Chuỗi tấn công: bơm một "response" chứa chỉ thị → agent `traffic_get` đọc nó như bằng chứng → agent có bash/exec, insert_assets, report_finding. Tức là **lối vào prompt injection cho một agent có khả năng thực thi lệnh**. Điều kiện: capture đang bật và agent có tra host đó; nhưng chi phí tấn công gần như bằng 0 và việc ghi thì xảy ra kể cả khi capture tắt.

Biến thể nhẹ hơn, không cần LLM: làm nhiễu/làm bẩn bằng chứng của bài pentest (ghi vào host của khách hàng những exchange chưa từng xảy ra) → báo cáo mất tính tin cậy.

### 6.4. DoS ổ đĩa / tài nguyên

Không có quota, không rate limit. Mỗi exchange ghi vào `index.sqlite`, body > 256 KiB ghi hẳn file `_blobs/...`, và FTS trigram tốn ~2x kích thước text (comment tại `traffic/traffic.go:113-116`). Kẻ tấn công đẩy body lớn liên tục → lấp ổ đĩa, kéo theo chết cả PostgreSQL/backend. Thêm nữa, `record()` giữ `t.wmu` và **chạy trước khi go-mitmproxy trả response** (chính comment ở `:109-112` nói vậy) → ghi nặng từ ngoài làm chậm trực tiếp traffic thật của agent.

### 6.5. Đọc dữ liệu đã ghi — *không* qua đường này

Cần nói rõ để không phóng đại: 8788 **không** cho đọc lại traffic đã ghi. Muốn đọc phải qua API 8787 (`GET /api/traffic*`, `server/server.go:793-799`) và API đó có auth. Rò rỉ dữ liệu đã ghi là kịch bản "đọc được file trên ổ đĩa" (`index.sqlite`, `_blobs` quyền `0644`), không phải kịch bản "chạm được port 8788".

### 6.6. Lấy CA key — *không* qua đường này

Tương tự: `mitmproxy-ca.pem` không được phục vụ qua 8788. Nhưng cần gộp hai vấn đề lại khi đánh giá rủi ro: port mở 8788 + CA key `0644` nằm trong workspace mà agent đọc được nghĩa là bề mặt tấn công "ký cert cho mọi domain" chỉ cách một lỗi local-read bất kỳ (hoặc một agent bị prompt-injected ở 6.3) — chứ không được bảo vệ bằng quyền file.

### 6.7. Bảng tổng hợp

| # | Làm được gì | Điều kiện | Xác nhận |
|---|---|---|---|
| 1 | Tunnel TCP tuỳ ý (loopback + mạng nội bộ) qua CONNECT | chạm được port | ✅ PoC |
| 2 | Open HTTP relay, đi qua egress proxy của operator | chạm được port | ✅ PoC (relay) |
| 3 | Bơm bằng chứng → prompt injection vào agent có bash | capture bật + agent tra host đó | ✅ ghi được; chuỗi tới LLM là suy luận |
| 4 | Làm bẩn / làm nhiễu bằng chứng pentest | chạm được port | ✅ PoC (exchange được ghi) |
| 5 | DoS ổ đĩa + làm chậm traffic thật | chạm được port | ✅ theo code, chưa đo |
| 6 | Tắt ghi log cho một host (poison `t.pass`) | gây được lỗi protocol | ⚠️ plausible, chưa PoC |
| 7 | Đọc traffic đã ghi | **không** qua 8788 (cần 8787 có auth, hoặc đọc file) | ❌ |
| 8 | Lấy CA private key | **không** qua 8788 (cần đọc file local / agent) | ❌ |

---

## 7. Khuyến nghị

Theo thứ tự hiệu quả/chi phí:

1. **`chmod 0600` cho `mitmproxy-ca.pem`.** Thư viện không làm, nên ARTEX phải tự `os.Chmod` sau `NewProxy` trong `traffic.Open` (`traffic/traffic.go:205-213`), đồng thời `0700` cho `_ca` (`:178-182`). Rẻ, không phá gì.
2. **Đưa `_ca` ra ngoài workspace browsable**, đúng cách JWT key đã được xử lý (`server/auth.go:40-76`) — hoặc tối thiểu loại trừ `_ca` khỏi `wsList`/`wsDownload` (`server/workspace.go`).
3. **Bật proxy auth.** Gọi `SetAuthProxy` với một token sinh tự động lúc khởi động, rồi ghi token vào env của worker (`agent/worker.go:205-225` đã là nơi duy nhất cấu hình client, nên chỉ phải sửa một chỗ: `HTTP_PROXY=http://artex:<token>@127.0.0.1:8788`). Đây là lớp phòng vệ duy nhất còn lại khi port bị lộ.
4. **Sửa các đường triển khai còn bind all-interfaces**: `Dockerfile:46` CMD → `-proxy 127.0.0.1:8788`, và `README.md:338` → ví dụ dùng loopback.
5. **Log cảnh báo rõ ràng khi bind ra ngoài loopback** (trong `traffic.Open`), vì vẫn cần hỗ trợ ca dùng thật là capture từ máy khác.
6. **Đóng listener khi tắt capture**: `SetTrafficEnabled(false)` (`server/manager.go:492-505`) nên gọi `proxy.Shutdown` (go-mitmproxy có sẵn `Proxy.Shutdown`, `proxy/proxy.go:84-86`), và/hoặc `record()` nên kiểm tra cờ capture.
7. **Giới hạn đích của CONNECT**: từ chối port không phải HTTP/HTTPS và từ chối đích loopback/link-local nếu không nằm trong scope — chặn đúng kịch bản 6.1.
8. **Hạn chế `t.pass`**: thêm TTL, hoặc cho xoá qua API, hoặc chỉ nhớ theo connection thay vì theo host vĩnh viễn.
9. Cân nhắc: quota dung lượng cho traffic store, và xem lại `SslInsecure: true` (`traffic/traffic.go:207`) — nó khiến lỗi TLS thật của target trở nên vô hình với agent, vì agent chỉ thấy cert do CA nội bộ ký lại.

---

## Phụ lục A: PoC đã chạy

Tất cả chạy cục bộ trong repo tại commit `d999b19`, bằng test tạm trong package `traffic` (đã xoá sau khi chạy, không commit).

**A.1 — Relay không credential + exchange được ghi + quyền file CA**

```
Proxy start listen at 127.0.0.1:18788
NO-AUTH RELAY status=200 body="INTERNAL-SECRET auth=\"Bearer victim-token\"" (target hits=1)
recorded exchanges=1 err=<nil>
CA file mitmproxy-ca-cert.cer mode=-rw-r--r--
CA file mitmproxy-ca-cert.pem mode=-rw-r--r--
CA file mitmproxy-ca.pem      mode=-rw-r--r--
```

Client không gửi `Proxy-Authorization`, đích là một HTTP server loopback. Request tới được đích, header `Authorization: Bearer victim-token` của victim được ghi nguyên văn vào index.

**A.2 — CONNECT tunnel TCP thô (không phải TLS, không phải HTTP)**

```
Proxy start listen at 127.0.0.1:18789
CONNECT 127.0.0.1:46709 (no credentials) -> "HTTP/1.1 200 Connection Established\r\n" err=<nil>
raw TCP tunnel reply="ECHO:RAW-TCP-PAYLOAD\n" err=<nil>
```

Đích là một TCP echo server (không HTTP, không TLS) → proxy vẫn mở tunnel và relay byte thô. Đây là xác nhận trực tiếp cho kịch bản pivot ở 6.1.

**A.3 — Quyền file do go-mitmproxy sinh ra**, kiểm tra riêng bằng cách gọi `cert.NewSelfSignCA` trực tiếp (umask `0022`):

```
root CA subject: CN=mitmproxy,O=mitmproxy
mitmproxy-ca-cert.cer mode=-rw-r--r-- size=1257
mitmproxy-ca-cert.pem mode=-rw-r--r-- size=1257
mitmproxy-ca.pem      mode=-rw-r--r-- size=2961
_ca dir               mode=drwxr-xr-x
```
