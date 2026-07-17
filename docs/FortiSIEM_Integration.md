# FortiSIEM — Illumio Quarantine Integration

Wires `illumio-quarantine.sh` v1.3.2 into FortiSIEM 7.5 so that
when an incident fires, the matching Illumio PCE workload is auto-quarantined
by label.

> **Compatibility note.** Vendor docs for FortiSIEM 7.5 do not definitively
> document whether `$token` substitution applies inside the custom Remediation
> Script's Script Content field (it applies for notification templates and
> ticketing integrations). Before wiring an automation policy to fire
> unattended, **verify on a test incident** that `${incidentSrcIpAddr}`,
> `${incidentId}`, and `${ruleName}` expand to real values by checking the
> emitted CEF line (`cs1`, `cs3`, `cs4`). If tokens arrive literal, either (a)
> wait for v2's HTTP webhook, or (b) pick a different token set — common
> working tokens include `$srcIpAddr`, `$incidentSrc`, `$incidentTarget`,
> `$incidentId`, `$ruleName`. Use ad-hoc "Remediate Incident" first, then
> switch to Automation Policy once token expansion is confirmed.

Shapes supported in v1.3.2:

| Shape | Recommended? |
|---|---|
| **SSH Remediation Script** | Yes — primary integration |
| Notification Policy HTTP POST | Deferred to v2 (needs the Python webhook) |

---

## 1. Prerequisites on the quarantine host (Linux)

```bash
sudo apt-get install -y curl jq ipcalc util-linux git
git clone <repo> /opt/illumio_Quarantine
cd /opt/illumio_Quarantine
git submodule update --init
```

### Credentials — env vars (recommended)

Put these in `/etc/environment` or a systemd `EnvironmentFile=`:

```bash
ILLUMIO_QUARANTINE_API_USER=api_xxxxxxxxxx
ILLUMIO_QUARANTINE_API_PASS=<PCE API secret>
ILLUMIO_QUARANTINE_PCE_URL=https://pce.lab.local:8443
ILLUMIO_QUARANTINE_ORG_ID=1
ILLUMIO_QUARANTINE_AUDIT_FILE=/var/log/illumio_quarantine.cef
```

This lets the FortiSIEM Remediation Script body stay short (it doesn't need
to repeat these values on every invocation).

### TLS certificate verification

`illumio-quarantine.sh` verifies PCE TLS certificates by default.
Only add `--insecure` in short-lived lab scenarios (for example, temporary
self-signed cert bootstrap). For production FortiSIEM automation, install the
correct CA chain on the quarantine host and keep `--insecure` off.

### Credentials — conf file (alternative)

```bash
cp config/quarantine.conf.example config/quarantine.conf
chmod 600 config/quarantine.conf
# edit API_USER / API_PASS / PCE_URL_BASE / ORG_ID
```

The script auto-discovers credentials files in this search order:
1. `$HOME/.config/illumio_quarantine/quarantine.conf`
2. `/etc/illumio_quarantine/quarantine.conf`

To explicitly load a repo-local file, use `--credentials-file ./config/quarantine.conf`.

### Local smoke

```bash
./illumio-quarantine.sh \
    --targets "<test workload>" --label-key Quarantine --label-value Severe \
    --non-interactive --dry-run --json
```

Must exit 0 (or 3 if the test target is not in PCE) and emit JSON on stdout.

---

## 2. Register the quarantine host in FortiSIEM CMDB

In FortiSIEM 7.5, the Remediation Script executes **on the enforceOn device**
— here, the quarantine host itself. The host must be registered first.

1. Navigate to **CMDB → Devices**, pick an appropriate device group in the
   left pane (e.g. Linux).
2. Click **+** in the main pane to add a new device.
3. In the **Summary** tab:
   - **Name**: `illumio-quarantine` (or your hostname)
   - **Access IP**: the host's reachable IP from the Supervisor/Collector
   - **Vendor**: Linux (or Generic)
   - **Model / Version**: to taste
   - **Device/App Group**: Linux Servers
4. Save.

---

## 3. Create an SSH credential and bind it to the host

1. Navigate to **Admin → Setup → Credentials**.
2. In **Step 1: Enter Credentials** → click **+**:
   - **Name**: `illumio-quarantine-ssh`
   - **Device Type**: Generic or Linux
   - **Access Protocol**: **SSH**
   - **Port**: `22`
   - **Password Config**: Manual (or CyberArk)
   - **User Name**: a low-privilege user on the quarantine host (e.g. `fortisiem-remediator`)
   - **Password**: the user's password
3. **Save.**
4. In **Step 2: Enter IP Range to Credential Associations** → click **+**:
   - **IP/Host Name**: the quarantine host's IP
   - **Credentials**: pick `illumio-quarantine-ssh`
5. **Save.**

> **Note on SSH key auth:** the FortiSIEM UI credential store requires a
> password (or CyberArk). Backend SSH can use keys, but the out-of-the-box
> flow is password-based. For production, use CyberArk or accept a
> password-rotated service account.

### Harden the service account

On the quarantine host, restrict the service account to run only the script:

```bash
# /etc/sudoers.d/illumio-quarantine
fortisiem-remediator ALL=(root) NOPASSWD: /opt/illumio_Quarantine/illumio-quarantine.sh
```

Disable shell access and allow only the specific command (SSH `ForceCommand`
pattern) if paranoid.

---

## 4. Register the Remediation Script

1. Navigate to **Resources → Automation → Remediations**, click **+**.
2. Fill in:
   - **Name**: `Illumio Quarantine Apply`
   - **Device Type**: Linux (or Generic — must match the device from step 2)
   - **Protocol**: **SSH**
   - **Remediation Script Name**: `illumio_quarantine_apply.sh` (label only — the script executed is what you put in Script Content)
   - **Remediation Script Content** (with env vars baked on the host):
     ```bash
     /opt/illumio_Quarantine/illumio-quarantine.sh \
         --targets "${incidentSrcIpAddr}" \
         --label-key Quarantine --label-value Severe \
         --mode append \
         --non-interactive --json \
         --correlation-id "${incidentId}" \
         --reason "${ruleName}"
     ```
     Without env vars baked (explicit paths):
     ```bash
     /opt/illumio_Quarantine/illumio-quarantine.sh \
         --targets "${incidentSrcIpAddr}" \
         --label-key Quarantine --label-value Severe \
         --mode append --non-interactive --json --parallel 4 \
         --correlation-id "${incidentId}" \
         --reason "${ruleName}" \
         --credentials-file /opt/illumio_Quarantine/config/quarantine.conf \
         --audit-file /var/log/illumio_quarantine.cef
     ```
     Lab-only (self-signed bootstrap):
     ```bash
     /opt/illumio_Quarantine/illumio-quarantine.sh \
         --targets "${incidentSrcIpAddr}" \
         --label-key Quarantine --label-value Severe \
         --mode append --non-interactive --json \
         --correlation-id "${incidentId}" \
         --reason "${ruleName}" \
         --insecure
     ```
   - **Description**: "Apply Quarantine:Severe label to Illumio workload matching the incident source IP."
3. **Save.**

Repeat for a release action with a different `--label-value` (e.g. `Released`)
or `--mode overwrite`.

---

## 5. Triggering the remediation

### 5a. Ad-hoc (operator-driven — use this first to validate)

1. `Incidents → List` → select an incident.
2. `Actions → Remediate Incident`.
3. Select `Illumio Quarantine Apply`.
4. Pick the enforcement point (Supervisor or Collector).
5. Pick the target device (the quarantine host registered in step 2).
6. Run.

Inspect the CEF line in `/var/log/illumio_quarantine.cef` to verify tokens
expanded correctly. `cs1=<incidentId>`, `cs3=<ruleName>`, `cs4=<srcIpAddr>`.

### 5b. Automation Policy (unattended)

Only wire this after ad-hoc token substitution is verified.

1. Navigate to **Admin → Settings → General → Automation Policy**, click **+**.
2. Fill in:
   - **Severity**: the threshold(s) that should auto-quarantine (e.g. HIGH, CRITICAL)
   - **Rules**: the incident rules that should fire this policy
   - **Time Range**: active window (usually 24/7)
   - **Affected Items**: device scope — which source IPs/devices trigger this
3. **Action → Run Remediation/Script**:
   - **Script**: pick `Illumio Quarantine Apply`
   - **Run On**: Supervisor or a specific Collector
   - **Enforce On**: the quarantine host
4. **Save.**

> **Throttle warning.** FortiSIEM 7.5 Automation Policy does not expose a
> native rate-limit / cooldown / de-dupe for remediation actions. A noisy rule
> can trigger thousands of invocations. Mitigations:
> - Narrow the rule's match criteria so it fires sparingly
> - Add a deduplication window at the rule level (if supported by the rule type)
> - Monitor `cn1` / `cn2` counters in the CEF audit — a sudden spike is your
>   signal to tighten the rule

---

## 6. Audit ingestion (CEF)

Have FortiSIEM's Linux collector agent tail `/var/log/illumio_quarantine.cef`
and forward as CEF. Parser mapping:

```
Vendor=Illumio  Product=Quarantine  Version=1.3.2
EventId=quarantine.action  Severity=5
cs1 → correlationId   cs2 → auditId       cs3 → reason
cs4 → targets         cs5 → labelKey      cs6 → labelValue
flexString1 → dryRun  cn1 → updatedCount  cn2 → failedCount
```

With `correlationId ↔ incidentId`, FortiSIEM can auto-close the incident
when the success event arrives.

---

## 7. Exit-code handling

| Code | Meaning | Suggested action |
|---|---|---|
| 0 | all matched, all quarantined | close incident |
| 2 | partial (some failed) | flag for operator; re-fire with same `correlation-id` to retry |
| 3 | no match (target not managed, unmanaged, or not in PCE) | note and close, or escalate |
| 4 | PCE unreachable, auth failure, or sync GET hit the PCE 500-result cap | page on-call; check VPN / PCE health / creds; if truncated, narrow targets |
| 5 | invalid input (bad flags, unknown label, malformed target term) | check rule template variables |
| 6 | credentials missing | check env vars / conf file / permissions |

---

## 8. Smoke test

SSH to the quarantine host as the service account and run:

```bash
/opt/illumio_Quarantine/illumio-quarantine.sh \
    --targets "<test hostname>" --label-key Quarantine --label-value Severe \
    --mode append --non-interactive --dry-run --json \
    --correlation-id "SMOKE-001" --reason "FortiSIEM smoke test" \
    --audit-file /var/log/illumio_quarantine.cef
```

If the lab PCE endpoint uses a temporary self-signed cert, add `--insecure`
for this smoke only, then remove it after CA trust is fixed.

Verify:
- exit `0` (or `3` for a fake host — both OK)
- JSON on stdout with `dry_run:true`
- CEF line appended with matching `cs1=SMOKE-001`
- FortiSIEM Collector receives the CEF event within a minute
- In the FortiSIEM UI, `Incidents → Incidents View` shows the event (filter by `correlationId=SMOKE-001`)

When dry-run is clean, drop `--dry-run` and re-run to do a real label
application. Verify in the Illumio PCE GUI that the workload gains the
`Quarantine:Severe` label while preserving its existing business labels.

---

---

# 中文說明 / Chinese

> **預設語言為英文。以下為繁體中文翻譯。**
> Default language is English. The section below is a Traditional Chinese translation.

---

# FortiSIEM — Illumio Quarantine 整合

將 `illumio-quarantine.sh` v1.3.2 串接至 FortiSIEM 7.5 中，以便當 incident 觸發時，
相符的 Illumio PCE workload 會透過標籤自動隔離。

> **相容性注意事項。** FortiSIEM 7.5 的原廠文件並未明確說明 `$token` 替換是否適用於
> 自訂 Remediation Script 的 Script Content 欄位（它適用於通知範本與工單系統整合）。
> 在將 Automation Policy 設定為無人值守觸發之前，請先**在測試 incident 上驗證**，
> 透過檢查輸出的 CEF 紀錄行（`cs1`, `cs3`, `cs4`）確認 `${incidentSrcIpAddr}`、
> `${incidentId}` 與 `${ruleName}` 是否能展開為真實數值。若 token 以字面形式傳達，
> 可選擇（a）等待 v2 的 HTTP webhook，或（b）改用其他 token 集合，例如
> `$srcIpAddr`、`$incidentSrc`、`$incidentTarget`、`$incidentId`、`$ruleName`。
> 請先使用特設的「Remediate Incident」，待確認 token 可成功展開後再切換至 Automation Policy。

v1.3.2 支援的整合形式：

| 形式 | 是否推薦 |
|---|---|
| **SSH Remediation Script** | 是 — 主要整合方式 |
| Notification Policy HTTP POST | 延後至 v2（需要 Python webhook） |

---

## 1. quarantine host 的先決條件（Linux）

```bash
sudo apt-get install -y curl jq ipcalc util-linux git
git clone <repo> /opt/illumio_Quarantine
cd /opt/illumio_Quarantine
git submodule update --init
```

### Credentials — env vars（推薦）

將以下內容放入 `/etc/environment` 或 systemd `EnvironmentFile=`：

```bash
ILLUMIO_QUARANTINE_API_USER=api_xxxxxxxxxx
ILLUMIO_QUARANTINE_API_PASS=<PCE API secret>
ILLUMIO_QUARANTINE_PCE_URL=https://pce.lab.local:8443
ILLUMIO_QUARANTINE_ORG_ID=1
ILLUMIO_QUARANTINE_AUDIT_FILE=/var/log/illumio_quarantine.cef
```

這能讓 FortiSIEM Remediation Script 本體保持簡短（不需要在每次呼叫時重複這些數值）。

### TLS 憑證驗證

`illumio-quarantine.sh` 預設會驗證 PCE TLS 憑證。只有在短期實驗室情境中（例如臨時
self-signed cert 引導）才加入 `--insecure`。正式生產環境的 FortiSIEM 自動化，請在
quarantine host 上安裝正確的 CA chain 並保持關閉 `--insecure`。

### Credentials — conf file（替代方案）

```bash
cp config/quarantine.conf.example config/quarantine.conf
chmod 600 config/quarantine.conf
# 編輯 API_USER / API_PASS / PCE_URL_BASE / ORG_ID
```

腳本會依照以下順序自動發掘 credentials file：
1. `$HOME/.config/illumio_quarantine/quarantine.conf`
2. `/etc/illumio_quarantine/quarantine.conf`

若要明確載入 repo 本地檔案，請使用 `--credentials-file ./config/quarantine.conf`。

### 本機 smoke 測試

```bash
./illumio-quarantine.sh \
    --targets "<test workload>" --label-key Quarantine --label-value Severe \
    --non-interactive --dry-run --json
```

必須回傳 exit 0（若測試目標不在 PCE 中則為 3），並在 stdout 輸出 JSON。

---

## 2. 在 FortiSIEM CMDB 中註冊 quarantine host

在 FortiSIEM 7.5 中，Remediation Script 會在 **enforceOn device 上執行**——在此即為
quarantine host 本身。必須先完成主機註冊。

1. 導覽至 **CMDB → Devices**，在左側窗格中挑選適當的裝置群組（例如 Linux）。
2. 在主窗格中點擊 **+** 以新增裝置。
3. 在 **Summary** 分頁中：
   - **Name**：`illumio-quarantine`（或您的 hostname）
   - **Access IP**：Supervisor/Collector 可觸及的該主機 IP
   - **Vendor**：Linux（或 Generic）
   - **Model / Version**：依需求設定
   - **Device/App Group**：Linux Servers
4. Save。

---

## 3. 建立 SSH credential 並綁定至主機

1. 導覽至 **Admin → Setup → Credentials**。
2. 在 **Step 1: Enter Credentials** → 點擊 **+**：
   - **Name**：`illumio-quarantine-ssh`
   - **Device Type**：Generic 或 Linux
   - **Access Protocol**：**SSH**
   - **Port**：`22`
   - **Password Config**：Manual（或 CyberArk）
   - **User Name**：quarantine host 上的低權限使用者（例如 `fortisiem-remediator`）
   - **Password**：該使用者的密碼
3. **Save。**
4. 在 **Step 2: Enter IP Range to Credential Associations** → 點擊 **+**：
   - **IP/Host Name**：quarantine host 的 IP
   - **Credentials**：選擇 `illumio-quarantine-ssh`
5. **Save。**

> **SSH key auth 注意事項：** FortiSIEM UI 憑證儲存區需要 password（或 CyberArk）。
> 後端 SSH 可以使用 keys，但開箱即用的流程是基於 password 的。
> 正式生產環境請使用 CyberArk 或接受定期輪替 password 的 service account。

### 強化 service account

在 quarantine host 上，限制 service account 只能執行該腳本：

```bash
# /etc/sudoers.d/illumio-quarantine
fortisiem-remediator ALL=(root) NOPASSWD: /opt/illumio_Quarantine/illumio-quarantine.sh
```

如需極致安全，請停用 shell 存取並僅允許特定指令（SSH `ForceCommand` 模式）。

---

## 4. 註冊 Remediation Script

1. 導覽至 **Resources → Automation → Remediations**，點擊 **+**。
2. 填寫：
   - **Name**：`Illumio Quarantine Apply`
   - **Device Type**：Linux（或 Generic——須與步驟 2 的裝置一致）
   - **Protocol**：**SSH**
   - **Remediation Script Name**：`illumio_quarantine_apply.sh`（僅為標籤；實際執行的是 Script Content 中的內容）
   - **Remediation Script Content**（已在主機上設定 env vars）：
     ```bash
     /opt/illumio_Quarantine/illumio-quarantine.sh \
         --targets "${incidentSrcIpAddr}" \
         --label-key Quarantine --label-value Severe \
         --mode append \
         --non-interactive --json \
         --correlation-id "${incidentId}" \
         --reason "${ruleName}"
     ```
     未設定 env vars（使用明確路徑）：
     ```bash
     /opt/illumio_Quarantine/illumio-quarantine.sh \
         --targets "${incidentSrcIpAddr}" \
         --label-key Quarantine --label-value Severe \
         --mode append --non-interactive --json --parallel 4 \
         --correlation-id "${incidentId}" \
         --reason "${ruleName}" \
         --credentials-file /opt/illumio_Quarantine/config/quarantine.conf \
         --audit-file /var/log/illumio_quarantine.cef
     ```
     僅限實驗室（self-signed cert 引導）：
     ```bash
     /opt/illumio_Quarantine/illumio-quarantine.sh \
         --targets "${incidentSrcIpAddr}" \
         --label-key Quarantine --label-value Severe \
         --mode append --non-interactive --json \
         --correlation-id "${incidentId}" \
         --reason "${ruleName}" \
         --insecure
     ```
   - **Description**：「對符合 incident 來源 IP 的 Illumio workload 套用 Quarantine:Severe 標籤。」
3. **Save。**

重複上述步驟以建立釋放動作，使用不同的 `--label-value`（例如 `Released`）或 `--mode overwrite`。

---

## 5. 觸發修復動作

### 5a. 特設模式（操作人員驅動——請先用此方式驗證）

1. `Incidents → List` → 選擇一個 incident。
2. `Actions → Remediate Incident`。
3. 選擇 `Illumio Quarantine Apply`。
4. 挑選執行點（Supervisor 或 Collector）。
5. 挑選目標裝置（步驟 2 中註冊的 quarantine host）。
6. Run。

檢查 `/var/log/illumio_quarantine.cef` 中的 CEF 紀錄行，確認 token 已正確展開：
`cs1=<incidentId>`、`cs3=<ruleName>`、`cs4=<srcIpAddr>`。

### 5b. Automation Policy（無人值守）

僅在確認 ad-hoc 模式下 token 替換正常後才設定此項。

1. 導覽至 **Admin → Settings → General → Automation Policy**，點擊 **+**。
2. 填寫：
   - **Severity**：應觸發自動隔離的嚴重度（例如 HIGH、CRITICAL）
   - **Rules**：應觸發此 policy 的 incident 規則
   - **Time Range**：啟用視窗（通常為 24/7）
   - **Affected Items**：裝置範圍——哪些來源 IP/裝置會觸發此 policy
3. **Action → Run Remediation/Script**：
   - **Script**：選擇 `Illumio Quarantine Apply`
   - **Run On**：Supervisor 或特定 Collector
   - **Enforce On**：quarantine host
4. **Save。**

> **節流警告。** FortiSIEM 7.5 Automation Policy 並未針對修復動作提供原生的
> rate-limit / cooldown / de-dupe 機制。雜訊過多的規則可能觸發數千次呼叫。
> 緩解措施：
> - 縮小規則的 match criteria，使其僅在必要時觸發
> - 在規則層級加入 deduplication window（如果該 rule type 支援）
> - 監控 CEF 稽核中的 `cn1` / `cn2` 計數器——突發峰值是需要收緊規則的信號

---

## 6. 稽核日誌攝取（CEF）

讓 FortiSIEM 的 Linux collector agent 追蹤 `/var/log/illumio_quarantine.cef`
並以 CEF 格式轉發。Parser 映射：

```
Vendor=Illumio  Product=Quarantine  Version=1.3.2
EventId=quarantine.action  Severity=5
cs1 → correlationId   cs2 → auditId       cs3 → reason
cs4 → targets         cs5 → labelKey      cs6 → labelValue
flexString1 → dryRun  cn1 → updatedCount  cn2 → failedCount
```

> v1.3.2 將 `dryRun` 從非標準的 `cs7` 改為 `flexString1` —
> CEF 標準只定義 `cs1`–`cs6`。既有的 parser 需同步更新。

透過 `correlationId ↔ incidentId` 對應，當 success 事件到達時，FortiSIEM 可自動關閉該 incident。

---

## 7. 退出碼處理

| 代碼 | 意義 | 建議動作 |
|---|---|---|
| 0 | 全部相符，全部已隔離 | 關閉 incident |
| 2 | 部分失敗（某些失敗） | 標記供操作人員檢視；以相同的 `correlation-id` 重新觸發來重試 |
| 3 | 無相符項目（目標未受管、非受管或不在 PCE 中） | 註記並關閉，或升級處理 |
| 4 | PCE 無法連線、auth 失敗，或同步 GET 觸及 PCE 500 筆上限 | 呼叫 on-call；檢查 VPN / PCE 狀態 / creds；若為截斷則縮小目標範圍 |
| 5 | 無效輸入（錯誤的 flags、未知 label、格式錯誤的目標詞） | 檢查 rule template 變數 |
| 6 | 遺失 credentials | 檢查 env vars / conf file / permissions |

---

## 8. Smoke 測試

以 service account 身分 SSH 至 quarantine host 並執行：

```bash
/opt/illumio_Quarantine/illumio-quarantine.sh \
    --targets "<test hostname>" --label-key Quarantine --label-value Severe \
    --mode append --non-interactive --dry-run --json \
    --correlation-id "SMOKE-001" --reason "FortiSIEM smoke test" \
    --audit-file /var/log/illumio_quarantine.cef
```

若實驗室 PCE endpoint 使用臨時 self-signed cert，請僅在此次 smoke 測試中加入 `--insecure`，
並在 CA 信任修復後將其移除。

驗證：
- exit `0`（假主機則為 `3`——兩者皆可）
- stdout 輸出附帶 `dry_run:true` 的 JSON
- CEF 紀錄行已附加，且 `cs1=SMOKE-001` 吻合
- FortiSIEM Collector 在一分鐘內收到 CEF 事件
- FortiSIEM UI 的 `Incidents → Incidents View` 顯示該事件（以 `correlationId=SMOKE-001` 篩選）

dry-run 確認無誤後，移除 `--dry-run` 並重新執行以進行真實的標籤套用。
在 Illumio PCE GUI 中確認 workload 取得 `Quarantine:Severe` 標籤，且現有業務標籤已保留。
