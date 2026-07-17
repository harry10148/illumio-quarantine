# illumio_Quarantine Roadmap

## v1.3.2 — correctness against real PCE API behavior (this release)

Driven by a full code review verified against Illumio PCE API documentation:

- **Sync-truncation guard**: the PCE silently caps synchronous collection
  GETs at 500 results. Full scans and `labels?key=` lookups now fail hard
  (exit 4) at the cap instead of quarantining on partial data; full scan
  requests `max_results=500` honestly. Async GET collections deferred to v2.
- **Status-code auth detection**: real PCE auth errors are HTTP 401/403 with
  a JSON *array* body (`[{"token":...,"message":...}]`), which the old
  object-shape check never matched (auth failures were misreported as exit
  3/5). All GETs now go through `pce_get` and branch on the HTTP status;
  the curl mock emits the real PCE error shape.
- **Strict target validation**: malformed CIDR/IP/range/prefix terms exit 5
  instead of silently matching nothing; ranges tolerate spaces around the
  separator; reversed ranges rejected; digits-and-dots garbage rejected.
- **CIDR normalization**: host addresses like `10.0.0.5/24` normalize to
  `10.0.0.0/24` before matching.
- **Decimal octet parsing**: leading-zero octets no longer parsed as octal
  (`08`/`09` previously caused bash arithmetic errors).
- **CEF**: `dry_run` moved from non-standard `cs7` to `flexString1`.
- Matching loop pre-flattens workloads with a single jq pass (one process
  per scan instead of ~6 per workload).
- Result temp dir honors `$TMPDIR` and is cleaned by EXIT/INT/TERM traps;
  bash >= 4.3 enforced at startup; interactive flow now picks the update
  mode *before* the final confirmation.

## v1.3.1 — bash, FortiSIEM-ready

Scope:
- Non-interactive CLI: `--non-interactive`, `--json`, `--dry-run`
- Target label resolution by `--label-id` or `--label-key`/`--label-value`
- Append-mode strips existing same-key labels before adding (B2)
- Server-side per-term workload lookup when all terms are precise, one full
  scan when CIDR/range/prefix is present
- `--parallel N` PUT pool (1..20)
- `--correlation-id` round-trip; `--reason` audit
- CEF audit line under flock
- Exit codes 0/2/3/4/5/6
- bats-core test suite
- Externalized credentials (CLI > env > file > default)

### Security hardening (post-initial 1.3.1)

- Curl credentials moved off command line via `-K` config file (no `/proc/*/cmdline` exposure)
- CEF extension values: spaces escaped to prevent audit log forgery
- Audit file and lock refuse symbolic links (atomic creation + stat)
- Credentials auto-discovery no longer searches CWD-relative `~/.illumio_quarantine`
- Exit code 4 (auth failure) when all workload PUTs fail with 401/403 (was exit 2)
- Documentation and version strings sync to 1.3.1 across README, FortiSIEM Integration guide, and CEF parser map

## v2.0.0 — Python, coexisting (planned)

Status: not started. v1 remains production.

Goals:
1. HTTP webhook `POST /webhook/v1/quarantine/apply` (bearer-token).
   Unlocks Splunk SOAR / QRadar SOAR without SSH.
2. Direct SIEM dispatchers: syslog UDP/TCP/TLS + Splunk HEC.
3. Multi-destination SIEM (`config.siem.destinations[]`).
4. pip-installable with `illumio-quarantine` console script.
5. systemd service template.
6. `quarantine/release` reverse endpoint.

Non-goals for v2:
- Replacing the bash v1 — both ship side-by-side.
- GUI (delegate to illumio_ops).

Likely layout (independent from illumio_ops):
```
illumio_quarantine/
├── cli.py  pce_client.py  workload_filter.py  audit.py
│   config.py  webhook.py  server.py
│   siem/{cef.py,json_line.py,transports.py}
└── tests/
```

## v2.1 (tentative)

- Per-token rate limiting
- Auto-release after N minutes unless held
- Multi-org PCE routing

## Non-plan

- Replacing Illumio PCE
- Policy authoring (see illumio_ops)

---

---

# 中文說明 / Chinese

> **預設語言為英文。以下為繁體中文翻譯。**
> Default language is English. The section below is a Traditional Chinese translation.

---

# illumio_Quarantine 發展藍圖

## v1.3.2 — 針對真實 PCE API 行為的正確性修正（本次發布）

源自一次以 Illumio PCE API 文件驗證的完整 code review：

- **同步截斷防護**：PCE 會將同步 collection GET 靜默截斷為 500 筆。全量掃描
  與 `labels?key=` 查詢在觸及上限時改為硬性失敗（exit 4），不再冒著以不完整
  資料執行隔離的風險；全量掃描誠實地請求 `max_results=500`。非同步 GET
  collections 延後至 v2。
- **以狀態碼偵測認證失敗**：真實 PCE 認證錯誤是 HTTP 401/403 加上 JSON
  「陣列」錯誤體（`[{"token":...,"message":...}]`），舊的物件形狀檢查永遠不會
  命中（認證失敗會被誤報為 exit 3/5）。所有 GET 改走 `pce_get` 並以 HTTP
  狀態碼分流；curl mock 改為輸出真實 PCE 錯誤格式。
- **目標詞嚴格驗證**：格式錯誤的 CIDR/IP/範圍/前綴以 exit 5 結束，不再靜默
  不匹配；範圍容忍分隔符前後空白；拒絕起訖顛倒的範圍與純數字點號垃圾輸入。
- **CIDR 正規化**：`10.0.0.5/24` 等主機位址在匹配前正規化為 `10.0.0.0/24`。
- **十進位 octet 解析**：前導零不再被當作八進位（`08`/`09` 先前會觸發 bash
  算術錯誤）。
- **CEF**：`dry_run` 從非標準的 `cs7` 改為 `flexString1`。
- 匹配迴圈改以單次 jq 預先展平（每次掃描一個行程，取代先前每個 workload
  約 6 個）。
- 結果暫存目錄尊重 `$TMPDIR` 並由 EXIT/INT/TERM trap 清理；啟動時強制要求
  bash >= 4.3；互動流程改為在最終確認「之前」選擇更新模式。

## v1.3.1 — bash，支援 FortiSIEM

範圍：
- 非互動式 CLI：`--non-interactive`、`--json`、`--dry-run`
- 透過 `--label-id` 或 `--label-key`/`--label-value` 解析目標標籤
- Append-mode 在新增前移除現有同鍵值（same-key）的標籤（B2）
- 當所有條件精確時，於伺服器端進行 per-term workload 查詢；有 CIDR/range/prefix 時進行一次完整掃描
- `--parallel N` PUT pool（1..20）
- `--correlation-id` 往返傳遞；`--reason` 稽核
- flock 鎖定下的 CEF 稽核紀錄行
- 退出碼 0/2/3/4/5/6
- bats-core 測試套件
- 外部化憑證（CLI > env > file > default）

### 安全強化（1.3.1 後期）

- Curl 憑證透過 `-K` 設定檔移出命令列（不會暴露於 `/proc/*/cmdline`）
- CEF 擴展值：空格轉義以防止稽核日誌偽造
- 稽核檔案及鎖檔拒絕符號連結（原子建立 + stat）
- 憑證自動探測不再搜尋 CWD 相對路徑 `~/.illumio_quarantine`
- 當所有工作負載 PUT 請求都以 401/403 失敗時，返回退出碼 4（認證失敗）（原為退出碼 2）
- 文件與版本字符串在 README、FortiSIEM 整合指南及 CEF 解析器對應表中同步為 1.3.1

## v2.0.0 — Python，共存運行（計畫中）

狀態：尚未開始。v1 仍為正式生產版本。

目標：
1. HTTP webhook `POST /webhook/v1/quarantine/apply`（bearer-token）。
   解鎖無需 SSH 的 Splunk SOAR / QRadar SOAR 整合。
2. 直接 SIEM 發送器：syslog UDP/TCP/TLS + Splunk HEC。
3. 多目的地 SIEM（`config.siem.destinations[]`）。
4. 透過 pip 安裝的 `illumio-quarantine` console script。
5. systemd 服務範本。
6. `quarantine/release` 反向端點。

v2 非目標：
- 取代 bash v1——兩者將並存發布。
- GUI（委派給 `illumio_ops`）。

可能的佈局（獨立於 `illumio_ops`）：
```
illumio_quarantine/
├── cli.py  pce_client.py  workload_filter.py  audit.py
│   config.py  webhook.py  server.py
│   siem/{cef.py,json_line.py,transports.py}
└── tests/
```

## v2.1（暫定）

- Per-token 速率限制
- N 分鐘後自動釋放，除非被保留
- Multi-org PCE 路由

## 非計畫

- 取代 Illumio PCE
- Policy authoring（請見 `illumio_ops`）
