# Security audit — `selfupdate/` (one-click update)

Phạm vi: `selfupdate/{selfupdate,github,stage,bootstrap}.go`, `server/update.go`,
`cmd/artex/main.go`, `start.sh` / `start.bat`, `Dockerfile`,
`.github/workflows/release.yml`, `web/src/app/(main)/system/settings/_components/update-card.tsx`.

Commit được audit: `d999b19` (branch `claude/selfupdate-security-audit-gvoo6b`).
Đây là audit đọc code (white-box), không chạy thử upgrade thật trên release live.

---

## 1. Toàn bộ luồng, theo thứ tự thực thi

Một lần upgrade hoàn chỉnh đi qua **3 lần khởi động process** (xem khối comment
`selfupdate/selfupdate.go:13-20`).

### Giai đoạn A — process cũ: check & stage

| # | Bước | Vị trí |
| --- | --- | --- |
| A1 | `GET /api/update/check` (sau JWT) → `NewClient(s.m.GlobalProxy())` → `relCache.get` → `FetchLatest` | `server/update.go:217-271` |
| A2 | So version: `CompareVersions(BuildVersion, tag)`; bản dev/git-describe → `comparable=false`, chặn update | `selfupdate/selfupdate.go:119-160`, `server/update.go:262-269` |
| A3 | `POST /api/update/apply` → lấy release **từ cache** (`force=false`) để cài đúng bản user đã thấy; `updHub.begin()` làm mutex in-process (trùng → 409); trả `202` rồi chạy goroutine với `s.ctx` | `server/update.go:277-319` |
| A4 | `checkWritable(p.Dir)` — probe `os.CreateTemp` trong thư mục cài, kiểm quyền ghi **trước khi** tải | `selfupdate/stage.go:69`, `:301-310` |
| A5 | Tìm asset theo tên suy ra từ nền tảng: `scopeweaver-<ver>-<goos>-<goarch>.zip` | `selfupdate/stage.go:73-77`, `selfupdate/github.go:128-130` |
| A6 | Tải `SHA256SUMS` (cap 1 MiB), parse, tra digest mong đợi của đúng asset đó. Không có entry → **từ chối** | `selfupdate/stage.go:79-87`, `:145-188` |
| A7 | Tải ZIP → ghi `scopeweaver.new.zip.part`, hash SHA-256 **streaming** qua `io.MultiWriter(f, h, pw)`, `f.Sync()`, so `pw.written` với `asset.Size` | `selfupdate/stage.go:98-102`, `:205-230` |
| A8 | **So checksum ZIP** với manifest (`strings.EqualFold`) → lệch là abort | `selfupdate/stage.go:104-107` |
| A9 | `extractBinary` — mở lại file `.part` từ đĩa, tìm entry theo basename `scopeweaver[.exe]`, ghi `scopeweaver.new.part` mode `0755`, cap 512 MiB | `selfupdate/stage.go:109-112`, `:257-297` |
| A10 | `smokeTest(binPath)` — `chmod 0755` + **exec `<bin> -h`**, timeout 30s, env `os.Environ() + ARTEX_SELFUPDATE_SMOKE=1` | `selfupdate/stage.go:113-115`, `selfupdate/bootstrap.go:178-199` |
| A11 | Hash lại binary đã extract → ghi `scopeweaver.new.sha256` (mode `0644`) → `os.Rename(binPath, p.New)` | `selfupdate/stage.go:119-129` |
| A12 | Ghi marker `scopeweaver.upgrade.json` (`from`/`to`/`attempts`/`staged_at`); lỗi ở đây **không** abort, chỉ cảnh báo "không có auto-rollback" | `selfupdate/stage.go:131-138` |
| A13 | SSE phát `staged`, chờ 1.5s cho client nhận, `requestRestart()` → `main` thoát **exit 75** | `server/update.go:304-316`, `cmd/artex/main.go:134-136` |

### Giai đoạn B — supervisor restart, process cũ: apply

| # | Bước | Vị trí |
| --- | --- | --- |
| B1 | `start.sh` / `start.bat` thấy code 75 → relaunch ngay, không backoff | `start.sh:46-66`, `start.bat:28-37` |
| B2 | `selfupdate.Bootstrap()` chạy **trước** khi mở DB / bind port; thoát sớm nếu `ARTEX_SELFUPDATE_SMOKE` được set | `cmd/artex/main.go:74-78`, `selfupdate/bootstrap.go:51-70` |
| B3 | `os.Stat(p.New)` tồn tại → `applyStaged` | `selfupdate/bootstrap.go:61-63`, `:77-104` |
| B4 | `verifyStaged` — đọc `p.Sum`, hash `p.New`, so sánh, rồi `smokeTest(p.New)` (lại `-h`) | `selfupdate/bootstrap.go:161-174` |
| B5 | Fail → `cleanStaged` (xoá `.new` + `.sha256`), xoá marker, `State{FailedStage:true}`, chạy tiếp bản cũ | `selfupdate/bootstrap.go:80-85` |
| B6 | `swap()` — `os.Remove(p.Old)` → `os.Rename(Current → Old)` → `os.Rename(New → Current)`; rename thứ 2 lỗi thì restore `Old → Current` | `selfupdate/bootstrap.go:205-222` |
| B7 | Giữ marker, `attempts = 0`, **exit 75** lần nữa | `selfupdate/bootstrap.go:94-103` |

### Giai đoạn C — supervisor restart, process mới: confirm hoặc rollback

| # | Bước | Vị trí |
| --- | --- | --- |
| C1 | `Bootstrap`: không còn `.new`, còn marker → `confirmOrRollback` | `selfupdate/bootstrap.go:65-69`, `:111-132` |
| C2 | `m.Attempts++`; `> maxAttempts (3)` → `rollback()`: `Current → .failed`, `Old → Current`, xoá marker, exit 75 | `selfupdate/bootstrap.go:112-125`, `:225-239` |
| C3 | Chưa quá hạn → ghi marker, `Continue` | `selfupdate/bootstrap.go:126-131` |
| C4 | `time.AfterFunc(SettleDelay=30s, Settle)` — sống đủ 30s thì xoá marker, upgrade coi là xong, giữ `.old` | `cmd/artex/main.go:106`, `selfupdate/bootstrap.go:138-158` |

Đường rollback thủ công: `POST /api/update/rollback` → `selfupdate.Rollback()`
(`bootstrap.go:243-270`) — smoke-test `.old` trước, rồi đổi chỗ `Current` ↔ `Old`
qua file trung gian `.swap` để chính rollback cũng đảo lại được.

---

## 2. URL tải: có hardcode không?

**Có hardcode một nửa — repo được pin, URL tải thật thì không.**

Hardcoded:

- `const Repo = "cskwork/scopeweaver"` — `selfupdate/github.go:16`. Comment nói
  rõ: cho config hoá sẽ thành đường RCE cho bất kỳ ai sửa được config. **Đúng.**
- `const latestURL = "https://api.github.com/repos/" + Repo + "/releases/latest"`
  — `selfupdate/github.go:19`. Không nối từ input runtime.
- Tên asset suy ra cục bộ từ `runtime.GOOS/GOARCH`, không lấy từ mạng
  (`github.go:128-130`).

**Không** hardcoded:

- URL tải ZIP và URL tải `SHA256SUMS` lấy nguyên từ field
  `browser_download_url` trong JSON của GitHub API (`github.go:47`,
  `stage.go:150`, `:206`). Tức là URL do phía server quyết định, client chỉ
  kiểm hai điều kiện:
  - `checkURL`: bắt buộc `https`, và hostname phải nằm trong allowlist
    (`github.go:78-86`).
  - `CheckRedirect` áp lại `checkURL` cho **từng hop** redirect, tối đa 10 hop
    (`github.go:68-74`). Đây là chỗ làm tốt — rất nhiều updater quên redirect.
- Allowlist (`github.go:24-30`): `api.github.com`, `github.com`,
  `objects.githubusercontent.com`, `release-assets.githubusercontent.com`,
  `raw.githubusercontent.com`.

Hệ quả (→ **F-02**): allowlist chỉ chặn *host*, không chặn *path*. `github.com`
và `raw.githubusercontent.com` là nơi **bất kỳ ai** cũng host được nội dung tuỳ
ý (`github.com/<attacker>/<repo>/releases/download/...`). Không có chỗ nào kiểm
`asset.URL` có thuộc `/cskwork/scopeweaver/` hay không. Việc pin `Repo` ở A1
không truyền được xuống bước tải ở A6/A7.

---

## 3. Checksum / chữ ký nào được verify, và trước hay sau khi ghi đĩa?

### Có gì

| Gate | Kiểm cái gì | Nguồn sự thật | Khi nào |
| --- | --- | --- | --- |
| G1 | SHA-256 của **ZIP** | asset `SHA256SUMS` của cùng release | A8, trước khi extract |
| G2 | Content-Length | `asset.Size` từ API | A7, cuối download |
| G3 | SHA-256 của **binary đã extract** | file `scopeweaver.new.sha256` cạnh nó | B4, lúc boot |
| G4 | Chạy được thật | `exec <bin> -h` | A10 và B4 |

**Không có chữ ký số nào được verify.** Không GPG, không minisign, không cosign /
Sigstore, không `actions/attest-build-provenance`. `SHA256SUMS` được sinh bằng
`sha256sum *.zip` (`.github/workflows/release.yml:82`; bản local:
`build.sh:249-260`) và upload như một asset thường, **không ký**. Grep toàn bộ
`.github/workflows/` cho `attest|cosign|gpg|minisign|sigstore` → không hit nào
ngoài `id-token` của `pages.yml`.

Nên trust anchor thật của toàn bộ chuỗi là: **TLS tới `api.github.com` + tính
toàn vẹn của tài khoản/token GitHub phát hành release**. `SHA256SUMS` nằm *cùng
một release* với ZIP nó bảo vệ, lấy qua *cùng một kênh*, nên ai thay được ZIP ở
tầng release cũng thay được manifest. Nó chống corruption trên đường truyền, chứ
không chống attacker kiểm soát được release hay forge được TLS. Thêm nữa,
`.github/workflows/repair-release-notices.yml:113` upload lại `SHA256SUMS` với
`--clobber` — manifest là **mutable** sau khi publish.

### Trước hay sau khi ghi đĩa

Thứ tự thực tế:

```
download → GHI ĐĨA (scopeweaver.new.zip.part) → verify G1 → extract (GHI ĐĨA, 0755)
→ exec smoke test (G4) → hash binary → ghi .sha256 → rename → .new
... restart ...
→ verify G3 (đọc .sha256 + hash .new) → exec smoke test (G4) → swap
```

- **ZIP được verify SAU khi đã ghi hết xuống đĩa**, không phải lúc đang
  stream vào buffer. Đây không phải lỗi — stream-hash rồi mới quyết định là cách
  bình thường, và file là `.part` (không phải tên cuối, chưa executable). ZIP
  **được** verify **trước khi** extract và **trước khi** có bất kỳ file
  executable nào xuất hiện. Thứ tự này đúng.
- Nhưng (→ **F-03**): hash ở G1 tính trên **byte stream trong bộ nhớ**
  (`io.MultiWriter(f, h, pw)` — `stage.go:220`), còn `extractBinary` **mở lại
  file từ đĩa** (`zip.OpenReader(zipPath)` — `stage.go:262`). Hai cái không được
  buộc với nhau. Cái được verify không phải cái được đọc.
- Binary sau extract **không** nằm trong `SHA256SUMS` (manifest chỉ phủ các ZIP).
  Toàn vẹn của nó bắc cầu qua ZIP.
- Lần verify thứ hai (G3, lúc boot) so `p.New` với `p.Sum` — mà `p.Sum` là một
  **file mode 0644 nằm ngay cạnh** `p.New` (`stage.go:123`). Ai ghi được `.new`
  thì ghi được `.sha256`. → **F-05**: gate này chống bit-rot/corruption, không
  chống tampering. Thông điệp lỗi `"SHA256 mismatch (download corrupted or
  tampered with)"` (`bootstrap.go:171`) và comment `stage.go:117-118` nói quá
  tính chất chống-tamper của nó.

---

## 4. Smoke test `-h` chạy ở quyền nào?

`exec.CommandContext(ctx, bin, "-h")` với `cmd.Env = append(os.Environ(),
smokeEnv+"=1")` — `bootstrap.go:185-187`.

- **Không hạ quyền.** Không `syscall.SysProcAttr`, không setuid/setgid, không
  user namespace, không seccomp, không `cmd.Dir`, không lọc env. Binary mới chạy
  **đúng uid/gid/capabilities của process server**.
- Trong Docker: `Dockerfile` không có chỉ thị `USER` → container chạy **root**,
  nên smoke test chạy **root**.
- Env được truyền **toàn bộ**: `ARTEX_PG_DSN`, API key của LLM provider, mọi
  secret của process đều vào tay binary vừa tải. (`bootstrap.go:186`)
- `bin` luôn là đường dẫn tuyệt đối (dẫn xuất từ `os.Executable()` trong
  `ResolvePaths`, `selfupdate.go:56-78`) → không có lookup `PATH`. Tốt.
- Timeout 30s, `ctx.Err()` được kiểm riêng để báo "timed out" thay vì lỗi exec
  chung; output cắt 300 ký tự trước khi vào message (`bootstrap.go:188-197`).

**`-h` kiểm được gì thật.** Tôi đã xác nhận bằng thực nghiệm: với `flag` package
của Go, `-h` trên một flagset không khai báo `-h` sẽ in usage rồi
`os.Exit(0)` ngay **trong `flag.Parse()`** — tức là trước `Bootstrap()`
(`cmd/artex/main.go:58` parse, `:74` Bootstrap). Nên:

- Biến chặn `ARTEX_SELFUPDATE_SMOKE` thực tế **không bao giờ được dùng tới** trên
  đường `-h`; nó là defense-in-depth cho trường hợp thứ tự trong `main` đổi.
  Comment `bootstrap.go:18-23` mô tả đúng ý đồ này.
- Smoke test **vẫn chạy toàn bộ `init()` của mọi package được import** (agent,
  config, db, server, locale...) cộng `locale.FromEnv` / `SetServerDefault`
  trong `main`. Không hề là một no-op.
- Nhưng nó **không** validate được DB, port, migration hay config — đúng như
  comment `bootstrap.go:108-110` thừa nhận, và đó là lý do cần thêm cơ chế
  đếm-attempt ở giai đoạn C.

→ **F-06**: bước gọi là "verification" này **là** thực thi code của artifact
chưa được chứng thực, ở quyền cao nhất mà process có. Ở A10 nó đứng *sau* gate
checksum G1 nên còn hợp lý. Ở B4 nó chỉ đứng sau G3, mà G3 lại dựa vào file
`.sha256` plantable → với attacker ghi được thư mục cài, `verifyStaged` trở
thành bộ máy exec hộ. Tương tự `Rollback()` (`bootstrap.go:252`) smoke-test
`p.Old` — một file hoàn toàn có thể bị plant — và còn `chmod 0755` cho nó trước
khi chạy (`bootstrap.go:179`).

---

## 5. Cửa sổ TOCTOU khi swap `scopeweaver.new`

Có **4 cửa sổ** riêng biệt, cộng 2 vấn đề liên quan về file handling. Tất cả đều
cần quyền ghi vào thư mục cài — xem phần "Điều kiện tiền đề" bên dưới.

**T1 — verify → swap (nghiêm trọng nhất).** `applyStaged` gọi
`verifyStaged(p)` (hash + smoke test theo **đường dẫn**), rồi gọi `swap(p)` cũng
theo **đường dẫn** (`bootstrap.go:80-87`). Không có fd nào được giữ xuyên hai
bước, không verify lại sau rename. Thay `p.New` giữa hai lời gọi → binary chưa
verify được rename vào `p.Current` và trở thành executable chính.

**T2 — download → extract.** Như mục 3: G1 hash stream, `extractBinary` đọc lại
từ đĩa (`stage.go:220` vs `:262`). Thay `scopeweaver.new.zip.part` trong khoảng
đó thì checksum không bắt được gì.

**T3 — extract/smoke → rename.** `smokeTest(binPath)` → `fileSHA256(binPath)` →
`os.Rename(binPath, p.New)` (`stage.go:113-126`). Binary được *đo* lại sau smoke
test nên T3 yếu hơn T1, nhưng cái được đo vẫn là đường dẫn, và `p.Sum` được ghi
*trước* rename.

**T4 — hai rename trong `swap`.** `Rename(Current→Old)` rồi
`Rename(New→Current)` (`bootstrap.go:210-213`). Giữa hai lệnh **không có file
nào ở `p.Current`**. Crash/mất điện đúng khoảnh khắc đó → `start.sh:14` kiểm
`[ -x "$BIN" ]`, thất bại, `exit 1`, supervisor dừng hẳn; phải vào sửa tay
(rename `.old` về). `rollback()` (`bootstrap.go:232-237`) có cùng cửa sổ này.
Đây là vấn đề *availability*, không phải integrity — và là giới hạn thật của
POSIX: không thể atomic-swap hai tên file bằng `rename(2)` thuần
(Linux có `renameat2(RENAME_EXCHANGE)` nhưng không portable sang Windows, mà
code này cố tình giữ một nhánh chung — `bootstrap.go:201-204`).

**T5 — tên file tạm đoán được + không `O_EXCL`/`O_NOFOLLOW`.** `zipPath`,
`binPath`, `p.Sum`, `p.New`, `p.Current + ".failed"`, `p.Current + ".swap"` đều
là tên tĩnh suy ra từ tên executable. `os.Create` (`stage.go:212`),
`os.OpenFile(O_CREATE|O_TRUNC|O_WRONLY)` (`stage.go:278`) và `os.WriteFile`
(`stage.go:123`, `selfupdate.go:105`) **đi theo symlink**. Pre-plant một symlink
ở các đường dẫn đó → ghi file tuỳ ý với quyền của server. Đối chiếu:
`checkWritable` dùng `os.CreateTemp` (tên random + `O_EXCL`) — làm đúng ở đúng
chỗ, chỉ là không nhất quán với phần còn lại.

**T6 — khoá chỉ in-process.** `updHub.running` (`server/update.go:142-152`) chặn
được hai request `apply` đồng thời trong *cùng một* process, nhưng không có
lockfile. Hai instance trỏ cùng thư mục (hoặc một process cũ chưa chết hẳn cùng
process mới sau exit 75) đua nhau trên cùng bộ `.new`/`.sha256`.

### Điều kiện tiền đề và mức độ thật

T1–T3, T5 đều cần **quyền ghi vào thư mục cài**. Nếu attacker đã chạy *với đúng
uid của server*, họ ghi thẳng lên `p.Current` được rồi — các cửa sổ này không
thêm gì. Mức độ thật nằm ở cấu hình mà **thư mục cài ghi được bởi một principal
thấp hơn principal chạy service**:

- service chạy root (mặc định của Docker image này, và của phần lớn hướng dẫn
  systemd), còn `/opt/scopeweaver` thuộc group deploy hoặc có mode `0775`/`0777`;
- nhiều user cùng dùng một máy pentest, binary nằm trong `$HOME` chung hoặc một
  share;
- `checkWritable` (`stage.go:301-310`) chỉ kiểm "ghi được không", **không** kiểm
  owner/mode của thư mục.

Trong các cấu hình đó T1 + T5 là **local privilege escalation** → root. Không có
chỗ nào trong package làm `Lstat`/`Stat` để từ chối thư mục cài ghi-được-bởi-group
hay world.

---

## 6. Global proxy trong UI có ảnh hưởng đường verify không?

**Có — proxy nằm trên đường fetch, không nằm trên đường verify, nhưng nó phủ
luôn cả nguồn của *giá trị so sánh*.** Chi tiết:

### Nó đi vào đâu

`server/update.go:237` và `:281`: `selfupdate.NewClient(s.m.GlobalProxy())`. Cùng
một client đó được dùng cho **cả ba** request: `FetchLatest` (API),
`fetchSums` (`SHA256SUMS`), và `download` (ZIP). Giá trị đến từ setting
`global_proxy` trong DB, sửa được qua `PATCH` settings
(`server/server.go:3560-3563` → `manager.go:813-833`), validate bởi
`traffic.ValidateProxyURL` (`traffic/traffic.go:334-351`: chỉ
`http`/`https`/`socks5`, phải có host).

### Phép verify thì sao

Bản thân phép so sánh SHA-256 là tính toán **local**, proxy không chạm được
(`stage.go:104-107`, `bootstrap.go:161-174`). Nhưng điều đó **không** có nghĩa
đường verify độc lập với proxy: *giá trị mong đợi* (`SHA256SUMS`) cũng đi qua
đúng proxy đó, cùng phiên, cùng trust store. Proxy không cần phá SHA-256 — chỉ
cần trả về một manifest khớp với ZIP của chính nó.

Rào chắn duy nhất chặn điều đó là TLS. Và TLS ở đây:

- `NewClient` dựng `http.Transport` **riêng**, không reuse default transport —
  comment `github.go:51-54` nói rõ mục đích là để `InsecureSkipVerify` ở nơi khác
  trong codebase không lây sang đây. Việc này **đúng và quan trọng**: repo có
  `InsecureSkipVerify: true` ở `mcphttp/client.go:107,132` và
  `enrich/enrich.go:97`, và chúng không chạm tới đường update. Đã verify bằng grep.
- `TLSClientConfig` để `nil` → dùng **system root pool**. **Không có cert
  pinning, không có public-key pinning cho GitHub.**

→ **F-07**: với một CA mà OS tin, một proxy trỏ vào MITM forge được *đồng thời*
JSON release, `SHA256SUMS` và ZIP → cài binary tuỳ ý, chạy ở quyền server. Điều
làm risk này **cao hơn bình thường** trong sản phẩm này: ScopeWeaver *tự sinh một
CA MITM* (`traffic/traffic.go:353-357`, `data/_ca/mitmproxy-ca-cert.pem`) và user
của một pentest tool thường cài CA đó vào trust store. Tôi **không** tìm thấy chỗ
nào trong repo tự cài CA vào system store (grep `update-ca-certificates`,
`security add-trusted-cert`, `certutil -addstore` → không hit), nên đây là rủi ro
từ hành vi vận hành của user, không phải do code làm. Nhưng hệ quả thì vẫn vậy:
trust anchor của update là *system* trust store của một cái máy đang chủ động
chạy MITM.

Thêm hai điểm nhỏ trên đường này:

- **Fail-open khi parse proxy lỗi.** `github.go:60-64`: `if pu, err :=
  url.Parse(p); err == nil { tr.Proxy = ... }` — lỗi parse thì **im lặng bỏ
  qua** và đi direct. `SetGlobalProxy` có validate nên không tới đây theo đường
  UI, nhưng giá trị do bản cũ ghi hoặc sửa trực tiếp DB sẽ làm update **lặng lẽ
  bypass proxy** mà user nghĩ là mọi egress đều qua proxy. Nên trả lỗi.
- **Proxy không che được verify nhưng che được *có update hay không*.** Timeout
  30 phút (`github.go:67`) cho download, 20s (`update.go:75`) cho check. Một
  proxy im lặng chặn/treo api.github.com giữ user ở bản cũ vô thời hạn; UI chỉ
  hiện lỗi "configure the global proxy in settings" (`github.go:102`). Đây là
  downgrade-by-denial, không bị ghi nhận như một sự cố bảo mật.
- Update traffic **đi chung đường egress với target traffic của engagement**.
  Nếu global proxy là một hop trong môi trường khách hàng, hạ tầng của khách
  hàng nằm trên đường cập nhật binary chạy root của chính công cụ pentest. Nên
  cân nhắc tách: `notify/http.go:82` đã làm đúng việc này cho notification
  (cố tình **không** dùng GlobalProxy); đường update thì không.

---

## 7. Findings

Severity là ước lượng trong ngữ cảnh deploy mặc định (single-admin, binary chạy
root trong Docker). Không có finding nào cho remote unauthenticated.

| ID | Severity | Finding |
| --- | --- | --- |
| F-01 | High (design) | Không có chữ ký số / provenance attestation. `SHA256SUMS` không ký, đi cùng release, qua cùng kênh, và còn mutable (`repair-release-notices.yml:113` `--clobber`). Trust = TLS + tài khoản GitHub. Một release bị thay (token maintainer bị lộ, CI bị chèn) qua được mọi gate. |
| F-02 | Medium | `asset.URL` lấy nguyên từ JSON, chỉ kiểm host. Không kiểm path prefix `/cskwork/scopeweaver/`. Allowlist chứa `github.com` + `raw.githubusercontent.com` — host mà bất kỳ ai cũng upload được nội dung tuỳ ý. Việc pin `Repo` không truyền xuống bước tải. |
| F-03 | Medium | TOCTOU T2: SHA-256 tính trên stream, `extractBinary` đọc lại file từ đĩa. Cái được verify ≠ cái được dùng. |
| F-04 | Medium | TOCTOU T1: `verifyStaged` → `swap` theo đường dẫn, không giữ fd, không re-verify sau rename. Cộng T5 (tên tạm tĩnh, `os.Create`/`os.OpenFile` không `O_EXCL`/`O_NOFOLLOW` → symlink-follow write). Với thư mục cài ghi-được-bởi-group và service chạy root → LPE. `checkWritable` không kiểm owner/mode. |
| F-05 | Medium | `p.Sum` (mode `0644`) nằm cạnh `p.New`: gate G3 lúc boot chống corruption, **không** chống tampering. Code/comment/message (`bootstrap.go:171`, `stage.go:117-118`) nói quá. |
| F-06 | Medium | Smoke test exec artifact chưa chứng thực ở **đúng quyền server** (root trong Docker), truyền **toàn bộ `os.Environ()`** gồm DSN và API key. `-h` thoát trong `flag.Parse` nhưng mọi `init()` của binary mới đã chạy. `Rollback()` còn `chmod 0755` + exec `p.Old` chỉ dựa trên sự tồn tại của file. |
| F-07 | Medium | Global proxy (UI) phủ cả API, `SHA256SUMS` và ZIP; TLS dùng system root pool, **không pin** GitHub cert/pubkey. Trên máy có CA MITM được tin (điều mà chính sản phẩm này sinh ra CA cho), một proxy do user cấu hình forge được cả manifest lẫn payload → RCE. Settings UI cho sửa proxy, trong khi `Repo` cố tình không cho sửa — bất đối xứng. |
| F-08 | Medium | Forced downgrade: `confirmOrRollback` đếm **số lần start**, không đếm crash; `defer settle.Stop()` (`main.go:107`) nghĩa là shutdown *sạch* trong vòng 30s vẫn **giữ** marker. 4 lần restart nhanh (vài `docker compose restart`, hay script giám sát) → tự động rollback về bản trước, có thể là bản có lỗ hổng đã fix. `Rollback()` không kiểm version. Không có log/alert nào gọi đây là downgrade. |
| F-09 | Low | Không cap kích thước ZIP tải về. Chỉ so `pw.written` với `asset.Size`, và `stage.go:226` bỏ qua check khi `Size == 0` → asset listing khai 0 cho phép ghi không giới hạn vào thư mục cài. `maxBinarySize` (512 MiB) chỉ áp cho extract. |
| F-10 | Low | `NewClient` fail-open: `url.Parse` lỗi → im lặng đi direct thay vì trả lỗi (`github.go:60-64`). Update bypass proxy mà user không biết. |
| F-11 | Low | T4: cửa sổ không-có-executable giữa hai `rename` trong `swap`/`rollback`. Crash đúng lúc đó → `start.sh:14` fail `exit 1`, cần can thiệp tay. (Giới hạn portability thật, nên document thay vì fix.) |
| F-12 | Low | T6: khoá chỉ in-process (`updHub.running`), không lockfile. Hai instance cùng thư mục, hoặc process cũ chồng lấn process mới sau exit 75, đua nhau trên `.new`/`.sha256`. |
| F-13 | Low | `cleanStaged` (`selfupdate.go:110-113`) không xoá `*.part`. Bị kill giữa download → `.zip.part` mồ côi vĩnh viễn, không có bước dọn lúc boot. Tương tự `.sha256` mồ côi nếu crash giữa `stage.go:123` và `:126`. |
| F-14 | Low | `applyStaged` xoá `.new` khi verify fail (`bootstrap.go:82`) → mất hiện vật để điều tra, trái với `rollback()` giữ `.failed` (`bootstrap.go:229-233`). Khi bị tấn công, đường fail chính lại là đường tự xoá bằng chứng. |
| F-15 | Low | Docker mode không chặn `apply`; chỉ cảnh báo trong `window.confirm` của UI (`update-card.tsx:154-161`). Binary mới ghi vào writable layer rồi mất khi recreate container, và `.old`/`.new` nằm ngoài volume `/app/data` nên cũng mất → rollback bất khả dụng sau recreate. |
| F-16 | Low | `relCache.get` giữ `c.mu` trong suốt lúc fetch (`update.go:85-104`), timeout 20s. Một proxy chậm serialize mọi caller của `/api/update/check` tới 20s mỗi lượt. Đánh đổi có chủ ý (comment `:82-83`) nhưng là một kênh DoS nhỏ. |
| F-17 | Info | Off-by-one trong docs: header `selfupdate.go:20` và `bootstrap.go:117` nói "three consecutive unstable starts", nhưng `m.Attempts++` rồi `> maxAttempts(3)` → rollback xảy ra ở **lần boot thứ 4**. |
| F-18 | Info | Cookie `artex_token` set bằng JS, `SameSite=Lax`, **không** `HttpOnly`/`Secure` (`web/src/lib/auth.ts:23`); token cũng đi trong query string cho SSE (`api.ts:175-182`). `SameSite=Lax` **đã** chặn CSRF cross-site POST lên `/api/update/apply`, và `ACAO: *` không kèm `Allow-Credentials` nên không mở credentialed cross-origin (`server.go:3921-3932`). Nhưng bất kỳ XSS nào = trigger update + đổi global proxy = RCE. Đường update làm nâng mức severity của mọi vấn đề auth/XSS khác trong app. |

### Điểm làm tốt (đáng giữ)

- Transport riêng cho update, cô lập khỏi `InsecureSkipVerify` ở `mcphttp`/`enrich`
  — đã verify bằng grep, không lây.
- HTTPS bắt buộc + allowlist áp **lại cho từng redirect hop** (`CheckRedirect`),
  cap 10 hop. Rất thường bị bỏ sót.
- `Repo` hardcoded có kèm lý do đúng trong comment.
- Verify ZIP **trước** extract; không file executable nào tồn tại trước gate G1.
- `parseSums` yêu cầu field đầu đúng 64 hex (`stage.go:190-202`) — chặn được kiểu
  "2 field prose cũng tính là checksum"; comment `:169-171` nói đúng lý do.
- Manifest cap 1 MiB; extract cap 512 MiB; chỉ extract entry khớp basename, bỏ
  qua mọi entry khác (không có zip-slip vì dst là đường dẫn tự chọn, không nối
  từ `entry.Name`).
- `checkWritable` pre-flight bằng `CreateTemp` (`O_EXCL`, tên random).
- `ResolvePaths` dùng `os.Executable()` + `EvalSymlinks`, **không** dùng CWD, có
  giải thích lý do (`selfupdate.go:41-42`).
- Bản dev / git-describe → `comparable=false` → chặn update, không ghi đè build
  đang test (`selfupdate.go:115-118`).
- Tất cả 4 endpoint update nằm sau `requireAuth`; chỉ `/api/auth/*` và
  `/api/health` được miễn (`server.go:671-677`, `auth.go:112-116`).
- `Bootstrap` chạy trước khi mở DB / bind port — đúng thứ tự.
- Marker ghi lỗi thì cảnh báo chứ không abort upgrade (`stage.go:136-137`) — đánh
  đổi được nêu rõ.
- Có auto-rollback + giữ `.old`; rollback thủ công tự nó cũng đảo lại được qua
  `.swap`.

---

## 8. Khuyến nghị, theo thứ tự ưu tiên

1. **Ký release** (F-01). Nhúng public key vào binary, verify signature của
   `SHA256SUMS` trước khi tin bất kỳ digest nào. `cosign sign-blob` với key
   trong GitHub secret, hoặc `actions/attest-build-provenance` + verify
   Sigstore bundle. Đây là fix duy nhất đổi được trust model; mọi fix khác chỉ
   là thu hẹp cửa sổ.
2. **Kiểm path của asset URL** (F-02): yêu cầu `u.Path` bắt đầu bằng
   `/cskwork/scopeweaver/` cho `github.com`, và cân nhắc bỏ
   `raw.githubusercontent.com` khỏi allowlist nếu đường update không dùng.
3. **Verify cái mình dùng, không verify cái mình vừa thấy** (F-03, F-04, F-05):
   - mở `.part` **một lần**, hash qua fd đó rồi `zip.NewReader` trên **cùng** fd
     (`zip.NewReader(f, size)` thay vì `zip.OpenReader(path)`);
   - thêm `O_EXCL` + `O_NOFOLLOW` cho mọi file do updater tạo, hoặc chuyển sang
     `os.CreateTemp` + rename như `checkWritable` đã làm;
   - trong `applyStaged`, re-verify **sau** khi rename vào `p.Current` và rollback
     ngay nếu lệch; hoặc thay `p.Sum` bằng digest đã ký từ bước 1 (lúc đó F-05
     tự biến mất).
4. **Siết thư mục cài** (F-04): `checkWritable` kiểm thêm owner và mode; từ chối
   (hoặc ít nhất log cảnh báo nổi bật) khi thư mục ghi được bởi group/world mà
   process chạy uid khác.
5. **Hạ quyền smoke test** (F-06): env tối thiểu (`cmd.Env` chỉ `PATH`, `HOME`,
   `ARTEX_SELFUPDATE_SMOKE`, locale) thay vì `os.Environ()`. Đây là one-liner và
   gỡ được việc trao secret cho artifact chưa chứng thực.
6. **Cân nhắc tách egress cho update** (F-07) như `notify/http.go` đã làm, hoặc
   pin GitHub public key / dùng một root pool riêng chỉ chứa CA công khai, hoặc
   tối thiểu cảnh báo rõ trong UI khi global proxy đang set rằng nó phủ cả
   đường update.
7. **Đếm crash, không đếm start** (F-08): đổi `confirmOrRollback` sang ghi marker
   "đã chạy đủ lâu" / dùng một flag clean-shutdown, và log rõ ràng khi rollback
   là một **downgrade**. Fail-open về trả lỗi thay vì direct trong `NewClient`
   (F-10).
8. **Cap kích thước download** (F-09): `io.LimitReader` trên body ZIP, bound =
   `min(asset.Size * 1.1, maxBinarySize)`; coi `Size == 0` là lỗi, không phải
   lý do bỏ check.
9. Sửa các điểm docs/dọn dẹp: off-by-one (F-17), `cleanStaged` xoá `.part`
   (F-13), giữ `.new` thất bại thành `.new.failed` thay vì xoá (F-14),
   document cửa sổ T4 và cách recover tay (F-11).

---

## 9. Những gì audit này **không** bao gồm

- Không chạy upgrade thật end-to-end trên release live; mọi kết luận từ đọc code
  cộng một thực nghiệm nhỏ xác nhận hành vi exit code `-h` của `flag` package.
- Không review `start.sh`/`start.bat` ngoài phần giao tiếp exit-code với
  `selfupdate`.
- Không đánh giá bảo mật pipeline release (quyền của runner, dependency CI,
  bảo vệ branch/tag) ngoài việc nhận định release **không** được ký.
- Không kiểm hành vi self-update trên Windows thật; `docs/VERIFICATION.md` cũng
  đã ghi nhận điều này ("Native Windows tests do not establish Windows
  self-update behavior"), và 10 fixture self-update Unix bị skip trên Windows.
- Không phân tích `mcphttp`/`enrich` ngoài việc xác nhận `InsecureSkipVerify` ở
  đó không chạm đường update.
