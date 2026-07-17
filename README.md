# illumio_Quarantine

Auto-quarantine Illumio PCE workloads by label. Callable interactively by an
operator or non-interactively by a SIEM/SOAR playbook (FortiSIEM primary).

**Current release: v1.3.2** (bash, requires bash >= 4.3).

> Future v2 (Python + HTTP webhook) is planned — see `docs/ROADMAP.md`.

---

## Install

```bash
sudo apt-get install -y curl jq ipcalc util-linux git
git clone <repo> /opt/illumio_Quarantine
cd /opt/illumio_Quarantine
git submodule update --init              # for the test harness only
```

## Configure — two paths

### Path 1: config file (recommended for operators)

```bash
cp config/quarantine.conf.example config/quarantine.conf
chmod 600 config/quarantine.conf
# edit API_USER / API_PASS / PCE_URL_BASE / ORG_ID
```

The script auto-discovers a credentials file in this search order when
`--credentials-file` is not given:
1. `$HOME/.config/illumio_quarantine/quarantine.conf`
2. `/etc/illumio_quarantine/quarantine.conf`

> **Note:** CWD-relative `./config/quarantine.conf` auto-discovery was removed
> for security (to prevent PCE redirect attacks via compromised repo copies).
> Use `--credentials-file ./config/quarantine.conf` to explicitly load it.

### Path 2: environment variables (recommended for SIEM/SOAR automation)

Bake these once into `/etc/environment`, systemd `EnvironmentFile=`, or the
SIEM agent's user profile:

```bash
ILLUMIO_QUARANTINE_API_USER=api_xxxxxxxxxx
ILLUMIO_QUARANTINE_API_PASS=<secret>
ILLUMIO_QUARANTINE_PCE_URL=https://pce.lab.local:8443
ILLUMIO_QUARANTINE_ORG_ID=1
ILLUMIO_QUARANTINE_AUDIT_FILE=/var/log/illumio_quarantine.cef
```

Env vars override the credentials file. CLI flags override env vars.

**Precedence**: `CLI flag` > `ILLUMIO_QUARANTINE_*` env var > `--credentials-file` parsed value > script default.

### TLS behavior (important)

- By default, `illumio-quarantine.sh` verifies the PCE TLS certificate.
- Use `--insecure` only in controlled lab/testing environments (for example, temporary self-signed cert setup).
- For production, install the proper CA chain on the host and do **not** use `--insecure`.

---

## Required vs optional arguments

### Required (non-interactive mode)

| Flag | What | Why required |
|---|---|---|
| `--targets <csv>` | IP/hostname/CIDR/range/prefix | Identifies who to act on — varies per call |
| **Exactly one of**:<br>`--label-id N`<br>**or**<br>`--label-key K --label-value V` | Which label to apply | Identifies the quarantine label |
| `--non-interactive` | Skip prompts | Required when invoked by SIEM (no TTY) |

### Credentials (one of)

| Source | How |
|---|---|
| Env vars (preferred for SIEM) | `ILLUMIO_QUARANTINE_API_USER` + `ILLUMIO_QUARANTINE_API_PASS` (+ optional `_PCE_URL`, `_ORG_ID`) |
| Credentials file (default search path) | Drop `quarantine.conf` at one of the 3 search paths (see above) |
| Explicit `--credentials-file <path>` | Overrides default search |

### Recommended for SIEM audit

| Flag | What | Env var alternative |
|---|---|---|
| `--json` | Structured stdout for SOAR to parse | — |
| `--correlation-id <id>` | SIEM incident ID — echoed in JSON + CEF, enables auto-close | — |
| `--reason <text>` | Human-readable cause — echoed to audit | — |
| `--audit-file <path>` | Append CEF line under flock (SIEM tails this) | `ILLUMIO_QUARANTINE_AUDIT_FILE` |

### Optional / tuning

| Flag | Default | Notes |
|---|---|---|
| `--mode append\|overwrite` | `append` | `append` preserves existing business labels; `overwrite` wipes |
| `--parallel N` | `1` | `1..20`; concurrent PUTs |
| `--dry-run` | off | Skip PUTs; still emit JSON + CEF |
| `--insecure` | off | Disable TLS certificate verification (`curl -k`), use only for controlled lab/testing |
| `--pce-url <url>` | from file/env | Override PCE base URL |
| `--org-id <id>` | from file/env | Override Org ID |

---

## Quick start — interactive (operator at a shell)

```bash
./illumio-quarantine.sh
# Uses auto-discovered credentials file. Prompts for targets, label, mode, confirmation.
```

## Quick start — minimum non-interactive

```bash
export ILLUMIO_QUARANTINE_API_USER=api_xxx
export ILLUMIO_QUARANTINE_API_PASS=<secret>
export ILLUMIO_QUARANTINE_PCE_URL=https://pce.lab.local:8443
export ILLUMIO_QUARANTINE_ORG_ID=1

./illumio-quarantine.sh \
    --targets "10.0.0.5" --label-id 134 \
    --non-interactive
```

4 arguments. Everything else has sensible defaults.

## Quick start — full SIEM-ready

With environment variables baked in once:

```bash
./illumio-quarantine.sh \
    --targets "${incidentSrcIpAddr}" \
    --label-key Quarantine --label-value Severe \
    --non-interactive --json \
    --correlation-id "${incidentId}" \
    --reason "${ruleName}"
```

Lab-only (self-signed cert bootstrap):

```bash
./illumio-quarantine.sh \
    --targets "${incidentSrcIpAddr}" \
    --label-key Quarantine --label-value Severe \
    --non-interactive --json \
    --correlation-id "${incidentId}" \
    --reason "${ruleName}" \
    --insecure
```

Without env vars (explicit paths everywhere):

```bash
./illumio-quarantine.sh \
    --targets "10.0.0.5,server1.lab.local,10.20.30.0/24" \
    --label-key Quarantine --label-value Severe \
    --mode append --non-interactive --json --parallel 4 \
    --correlation-id "INC-12345" \
    --reason "Malware beaconing rule" \
    --credentials-file /opt/illumio_Quarantine/config/quarantine.conf \
    --audit-file /var/log/illumio_quarantine.cef
```

---

## FortiSIEM integration

See [`docs/FortiSIEM_Integration.md`](docs/FortiSIEM_Integration.md) for the
complete FortiSIEM 7.5 setup (CMDB registration, SSH credential binding,
Remediation Script body, Automation Policy trigger, CEF audit parser).

## CLI reference

```bash
./illumio-quarantine.sh --help
```

## JSON schema

See `docs/FortiSIEM_Integration.md` §Audit for the CEF field mapping. The
`--json` output contains:

```
audit_id, correlation_id, mode, label{href,key,value},
requested_targets[], search_strategy, matched[], updated[],
skipped_already_labeled[], failed[],
counts{requested,matched,updated,skipped,failed},
parallel, dry_run, duration_ms, exit_code
```

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success (all matched workloads were updated or idempotently skipped) |
| 2 | Partial failure (some PUTs failed; check `failed[]` in JSON) |
| 3 | No managed workload matched any target |
| 4 | PCE unreachable, auth failure, or a sync collection GET hit the PCE 500-result cap |
| 5 | Invalid input (bad flags, unknown label, malformed target term) |
| 6 | Credentials missing |

## Limitations

- **PCE sync collection cap (500).** The PCE silently truncates synchronous
  collection GETs to the latest 500 results. When a full workload scan
  (CIDR/range/prefix targets) or a `labels?key=` lookup returns 500 items,
  the script refuses to continue (exit 4) rather than risk quarantining on
  partial data. Environments above the cap need async GET collections
  (`Prefer: respond-async`) — planned for v2.
- **Target validation is strict.** Malformed targets (bad CIDR, invalid
  octets, reversed ranges, non-numeric prefix terms like `web01.`) exit 5
  instead of silently matching nothing. CIDR host addresses are normalized
  to their network (`10.0.0.5/24` → `10.0.0.0/24`).
- **`--json` pre-flight errors.** Failures before the run starts (label
  resolution, credential errors, truncation) print plain text to stderr and
  emit no JSON on stdout — SIEM playbooks must key off the exit code.

## Tests

```bash
scripts/run_tests.sh
```

Single-test file:
```bash
scripts/run_tests.sh tests/test_args.bats
```

---

---

# 中文說明 / Chinese

> **預設語言為英文。以下為繁體中文翻譯。**
> Default language is English. The section below is a Traditional Chinese translation.

---

# illumio_Quarantine

透過標籤自動隔離 Illumio PCE workloads。可由操作人員互動式呼叫，或透過 SIEM/SOAR
playbook（主要為 FortiSIEM）非互動式呼叫。

**目前版本：v1.3.2**（bash，需要 bash >= 4.3）。

> 計畫推出未來的 v2（Python + HTTP webhook）— 請參閱 `docs/ROADMAP.md`。

---

## 安裝

```bash
sudo apt-get install -y curl jq ipcalc util-linux git
git clone <repo> /opt/illumio_Quarantine
cd /opt/illumio_Quarantine
git submodule update --init              # 僅用於測試框架
```

## 設定 — 兩種途徑

### 途徑 1：config file（推薦給操作人員）

```bash
cp config/quarantine.conf.example config/quarantine.conf
chmod 600 config/quarantine.conf
# 編輯 API_USER / API_PASS / PCE_URL_BASE / ORG_ID
```

當未提供 `--credentials-file` 時，腳本會依照以下搜尋順序自動發掘 credentials file：
1. `$HOME/.config/illumio_quarantine/quarantine.conf`
2. `/etc/illumio_quarantine/quarantine.conf`

> **注意：** CWD 相對路徑的 `./config/quarantine.conf` 自動發掘已移除，
> 以防止安全問題（防止 PCE 透過受危的 repo 複本進行重定向攻擊）。
> 若要明確載入它，請使用 `--credentials-file ./config/quarantine.conf`。

### 途徑 2：環境變數（推薦用於 SIEM/SOAR 自動化）

將以下內容一次性寫入 `/etc/environment`、systemd `EnvironmentFile=`，或 SIEM agent 的使用者設定：

```bash
ILLUMIO_QUARANTINE_API_USER=api_xxxxxxxxxx
ILLUMIO_QUARANTINE_API_PASS=<secret>
ILLUMIO_QUARANTINE_PCE_URL=https://pce.lab.local:8443
ILLUMIO_QUARANTINE_ORG_ID=1
ILLUMIO_QUARANTINE_AUDIT_FILE=/var/log/illumio_quarantine.cef
```

Env vars 覆蓋 credentials file。CLI flags 覆蓋 env vars。

**優先順序**：`CLI flag` > `ILLUMIO_QUARANTINE_*` env var > `--credentials-file` 解析值 > 腳本預設值。

### TLS 行為（重要）

- 預設情況下，`illumio-quarantine.sh` 會驗證 PCE TLS 憑證。
- `--insecure` 僅在受控實驗室/測試環境（例如臨時 self-signed cert）中使用。
- 生產環境請在主機上安裝正確的 CA chain，**不要**使用 `--insecure`。

---

## 必填與選用參數

### 必填（非互動模式）

| 旗標 (Flag) | 說明 | 為何必填 |
|---|---|---|
| `--targets <csv>` | IP/hostname/CIDR/range/prefix | 識別要操作的對象 |
| **下列擇一**：<br>`--label-id N`<br>**或**<br>`--label-key K --label-value V` | 指定要套用的標籤 | 識別隔離標籤 |
| `--non-interactive` | 略過提示 | SIEM 呼叫時必填（無 TTY） |

### Credentials（擇一）

| 來源 | 方式 |
|---|---|
| Env vars（SIEM 偏好） | `ILLUMIO_QUARANTINE_API_USER` + `ILLUMIO_QUARANTINE_API_PASS`（+ 選用的 `_PCE_URL`, `_ORG_ID`） |
| Credentials file（預設搜尋路徑） | 將 `quarantine.conf` 放置於 3 個搜尋路徑之一（見上方） |
| 明確指定 `--credentials-file <path>` | 覆蓋預設搜尋 |

### SIEM 稽核建議選項

| 旗標 (Flag) | 說明 | Env var 替代方案 |
|---|---|---|
| `--json` | 供 SOAR 解析的結構化 stdout | — |
| `--correlation-id <id>` | SIEM 事件 ID — 在 JSON + CEF 中回應，啟用自動關閉 | — |
| `--reason <text>` | 人類可讀的原因 — 記入稽核日誌 | — |
| `--audit-file <path>` | 以 flock 鎖定方式附加 CEF 紀錄（SIEM 追蹤此檔） | `ILLUMIO_QUARANTINE_AUDIT_FILE` |

### 選用 / 微調參數

| 旗標 (Flag) | 預設值 | 備註 |
|---|---|---|
| `--mode append\|overwrite` | `append` | `append` 保留現有業務標籤；`overwrite` 抹除 |
| `--parallel N` | `1` | `1..20`；併發 PUTs 數量 |
| `--dry-run` | off | 略過 PUTs；仍輸出 JSON + CEF |
| `--insecure` | off | 停用 TLS 憑證驗證（`curl -k`），僅限受控實驗室 |
| `--pce-url <url>` | 來自 file/env | 覆寫 PCE 基礎 URL |
| `--org-id <id>` | 來自 file/env | 覆寫 Org ID |

---

## 快速開始 — 互動模式（操作人員於 shell 執行）

```bash
./illumio-quarantine.sh
# 使用自動發掘的 credentials file。提示輸入 targets、label、mode 與確認。
```

## 快速開始 — 最小化非互動模式

```bash
export ILLUMIO_QUARANTINE_API_USER=api_xxx
export ILLUMIO_QUARANTINE_API_PASS=<secret>
export ILLUMIO_QUARANTINE_PCE_URL=https://pce.lab.local:8443
export ILLUMIO_QUARANTINE_ORG_ID=1

./illumio-quarantine.sh \
    --targets "10.0.0.5" --label-id 134 \
    --non-interactive
```

4 個參數。其餘皆有合理的預設值。

## 快速開始 — 完整 SIEM 就緒模式

一次性寫入 environment variables 後：

```bash
./illumio-quarantine.sh \
    --targets "${incidentSrcIpAddr}" \
    --label-key Quarantine --label-value Severe \
    --non-interactive --json \
    --correlation-id "${incidentId}" \
    --reason "${ruleName}"
```

僅限實驗室（self-signed cert 引導）：

```bash
./illumio-quarantine.sh \
    --targets "${incidentSrcIpAddr}" \
    --label-key Quarantine --label-value Severe \
    --non-interactive --json \
    --correlation-id "${incidentId}" \
    --reason "${ruleName}" \
    --insecure
```

不使用 env vars（全面使用明確路徑）：

```bash
./illumio-quarantine.sh \
    --targets "10.0.0.5,server1.lab.local,10.20.30.0/24" \
    --label-key Quarantine --label-value Severe \
    --mode append --non-interactive --json --parallel 4 \
    --correlation-id "INC-12345" \
    --reason "Malware beaconing rule" \
    --credentials-file /opt/illumio_Quarantine/config/quarantine.conf \
    --audit-file /var/log/illumio_quarantine.cef
```

---

## FortiSIEM 整合

完整的 FortiSIEM 7.5 設定（CMDB 註冊、SSH 憑證綁定、Remediation Script 本體、
Automation Policy 觸發器、CEF 稽核解析器）請見
[`docs/FortiSIEM_Integration.md`](docs/FortiSIEM_Integration.md)。

## CLI 參考

```bash
./illumio-quarantine.sh --help
```

## JSON Schema

CEF 欄位映射請見 `docs/FortiSIEM_Integration.md` §Audit。`--json` 輸出包含：

```
audit_id, correlation_id, mode, label{href,key,value},
requested_targets[], search_strategy, matched[], updated[],
skipped_already_labeled[], failed[],
counts{requested,matched,updated,skipped,failed},
parallel, dry_run, duration_ms, exit_code
```

## 退出碼

| 代碼 | 意義 |
|---|---|
| 0 | 成功（所有相符的 workloads 皆已更新或以冪等方式略過） |
| 2 | 部分失敗（部分 PUTs 失敗；請檢查 JSON 中的 `failed[]`） |
| 3 | 沒有受管的 workload 匹配任何目標 |
| 4 | PCE 無法連線、auth 失敗，或同步 collection GET 觸及 PCE 的 500 筆上限 |
| 5 | 無效的輸入（錯誤的 flags、未知 label、格式錯誤的目標詞） |
| 6 | 遺失 credentials |

## 限制

- **PCE 同步 collection 上限（500 筆）。** PCE 會將同步 collection GET 靜默
  截斷為最新 500 筆。當全量 workload 掃描（CIDR/範圍/前綴目標）或
  `labels?key=` 查詢回傳 500 筆時，腳本會拒絕繼續（exit 4），避免在不完整
  的資料上執行隔離。超過上限的環境需要非同步 GET collections
  （`Prefer: respond-async`）— 規劃於 v2 實作。
- **目標詞嚴格驗證。** 格式錯誤的目標（無效 CIDR、非法 octet、起訖顛倒的
  範圍、非數字前綴如 `web01.`）會以 exit 5 結束，而不是靜默不匹配。CIDR
  主機位址會正規化為其網路位址（`10.0.0.5/24` → `10.0.0.0/24`）。
- **`--json` 前期錯誤。** 執行開始前的失敗（label 解析、credentials 錯誤、
  截斷防護）只會輸出純文字到 stderr，stdout 不會有 JSON — SIEM playbook
  必須以 exit code 判斷。

## 測試

```bash
scripts/run_tests.sh
```

單一測試檔案：
```bash
scripts/run_tests.sh tests/test_args.bats
```
