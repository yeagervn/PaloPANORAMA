# PaloRuleSearch Suite (bản PANORAMA) — Tài liệu đầy đủ (kiến trúc + luật vận hành từng tool)

> Tài liệu này là **nguồn chân lý duy nhất** cho bản Suite chạy trên **Panorama** (thay vì
> Firewall standalone như bản gốc). Toàn bộ **luật nghiệp vụ** (thứ tự tier, điều kiện exact-scope,
> nguyên tắc "chỉ khớp chính xác", format export, hành vi shadow/audit...) được **giữ nguyên 100%**
> so với bản Firewall standalone. Phần **duy nhất thay đổi** là **lớp hạ tầng lấy dữ liệu**: cách
> lấy config, cấu trúc phân cấp Device Group/Shared/Template, thứ tự đánh giá rule trên Panorama,
> và các API cần tham số `target` (serial thiết bị quản lý). Mọi thay đổi hạ tầng được liệt kê tập
> trung ở **PHẦN 0**; các Phần I-V áp dụng nguyên PHẦN 0 vào từng tool cụ thể.
>
> Từ lần cập nhật này trở đi, mỗi khi có thay đổi mới, chỉ bổ sung vào mục **"XIV. Nhật ký thay
> đổi gần nhất"** ở cuối file — KHÔNG viết lại các mục luật nghiệp vụ (trừ khi chính luật đó bị sửa).

---

# TÌNH TRẠNG HIỆN TẠI (ảnh chụp bản mới nhất)

> **Mục này PHẢI được cập nhật trong CÙNG lần bàn giao với mọi lần sửa code** (quy tắc V.4).
> Ai tiếp nhận bảo trì đọc đúng mục này là biết ngay: bản hiện tại là gì, đã được kiểm chứng
> tới đâu, và **cái gì CHƯA được kiểm chứng** — không phải đọc ngược toàn bộ changelog XIV.

| | |
|---|---|
| **Cập nhật lúc** | 2026-10-25 |
| **Repo / branch** | `yeagervn/PaloPANORAMA` — branch **`main`** (bản này được lấy làm main) |
| **Commit HEAD** | xem commit mới nhất trên nhánh làm việc (bản gộp định danh bằng SHA256 bên dưới) |
| **Sản phẩm chính** | `PaloPANORAMA_single.py` (bản gộp 1 file, SHA256 `bfef091f007f50786e3b7d8226c34433c466b05d356b79479cec3febe170f435`, 253161 ký tự, nhúng 22 file py) |
| **Sinh lại bản gộp** | `python tools/build_panorama_single.py` — kiểm tra lệch: `--check` (exit 1 nếu lệch), idempotent |
| **Bộ test chung** | `python -m unittest discover -s tests -q` → **231 test, OK (skipped=4)**; trên máy CÓ Tk (`xvfb-run python3.12 -m unittest discover -s tests -q`) → **243 test, OK, 0 skip** |
| **Nghiệm thu trên Panorama giả lập** | `python testlab/run_all_features.py --auto` → **68/68 PASS** (xem PHẦN VI) |
| **3 package** | `check_rule_pan/`, `check_ip_pan/`, `check_audit_pan/` — độc lập 100% về code/namespace/output/log |

`skipped=4` là **toàn bộ các test cần cửa sổ Tk thật** (`tests/test_gui_thread_safety.py::TestCloseWhileWorkerRunning`
và 3 file `tests/test_gui_e2e_*.py`): không có `$DISPLAY` thì tự `skipTest("khong co DISPLAY (chay qua xvfb-run)")`.
Chạy `xvfb-run -a python3.12 -m unittest discover -s tests -q` thì **0 skip** (243 test) — đó mới là
con số nghiệm thu đầy đủ; 231/skipped=4 chỉ là con số trên máy/CI không có X server.

## Đã kiểm chứng tới đâu (và CHƯA tới đâu)

| Hạng mục | Trạng thái | Bằng chứng |
|---|---|---|
| Luật nghiệp vụ 3 tool — **giữ nguyên 100%** so với bản Firewall standalone | **Đã kiểm chứng** | 243 test (có Tk), trong đó port nguyên 9 bộ test nghiệp vụ của bản standalone + differential 1500 kịch bản ngẫu nhiên |
| 8 điểm đặc thù Panorama 0.1 → 0.8 (chuỗi DG, thừa kế object, lắp ráp 6 bước, candidate, Live Match/Zone/hit-count cần `target`, xpath ghi theo DG) | **Đã kiểm chứng** | `tests/test_panorama_infra.py` (36 test) + **68/68** ca nghiệm thu lab |
| Lớp gọi API thật (HTTPS, op-command, parse phản hồi, lệnh ghi candidate) | **Đã kiểm chứng trên Panorama GIẢ LẬP** | `testlab/run_all_features.py --auto` |
| Bản gộp 1 file | **Đã kiểm chứng** | build idempotent + SHA256 ở trên; giải nén zip nhúng, import lại 9 module logic từ bộ nhớ, xác nhận bản nhúng **không cũ hơn** source |
| **Chính bộ sinh bản gộp** (`tools/build_panorama_single.py`) | **Đã kiểm chứng** | `tests/test_build_panorama_single.py` (7 ca): `_replace` báo lỗi khi mất mốc neo / bỏ qua khi đã vá, `done_if` nhiều mốc, build **idempotent** (chạy 2 lần ra byte y hệt), `on_close()` sinh ra gọi `shutdown()` cho **cả 3 tab**, sinh lại đúng từ dạng `on_close` cũ 2 tab, và **sống sót khi `main()` bị sửa tay** |
| **GUI thật — lái hết luồng nghiệp vụ qua giao diện, CẢ 3 TAB** | **Đã kiểm chứng (headless)** | 3 file E2E lái thật giao diện trên **Panorama giả lập của testlab**: `tests/test_gui_e2e_check_rule.py` (Load Config → nhập tay → Check → chạy file mẫu → sinh đúng 1 `Result_*.xlsx` cạnh file input → đóng cửa sổ giữa chừng), `test_gui_e2e_check_ip.py` (Connect → chọn DG-HN → dán IP → Check/Export → Excel 2 sheet; ca để trống; ca Cancel), `test_gui_e2e_check_audit.py` (Connect → tick cả 3 detector → Check → Export; ca bỏ tick hết; ca D6 không bao giờ gọi commit) |
| **GUI thật — nhìn bố cục trên Windows** | **CHƯA** | mọi kiểm chứng headless qua Xvfb trên Linux. `testlab/README.md` mục 2 ghi sẵn thông số (`127.0.0.1:8443`, DG `DG-HN`, target `001122334455`) |
| **Chạy với Panorama THẬT** | **CHƯA** | cần 1 lần chạy **chỉ đọc** (không bấm Import) trên Panorama thật trước khi phát hành |
| Schema `<shared>` của `show rule-hit-count` | **CHƯA xác nhận trên thiết bị thật** | để **best-effort có chủ đích**: Panorama từ chối → log cảnh báo + đi tiếp, rule trong DG vẫn đủ hit-count; kịch bản bị từ chối đã có 1 ca trong lab |
| Rule **cục bộ trên firewall** (0.3 bước 3) | **Chưa có đường nạp** | hàm đọc + vị trí lắp ráp đã đúng, nhưng GUI chưa có ô nạp file config firewall → mặc định `local_rules=None` |
| `security-policy-match`, `rule-hit-count` | **Mô phỏng** | lab duyệt theo đúng thứ tự lắp ráp 0.3; rất sát nhưng **không phải dataplane/Policy Optimizer thật** |

---

# PHẦN 0 — DELTA HẠ TẦNG: FIREWALL STANDALONE → PANORAMA

**Đọc phần này TRƯỚC khi đọc bất kỳ phần nào khác.** Đây là danh sách đầy đủ mọi khác biệt hạ
tầng. Bất kỳ chỗ nào trong Phần I-V nhắc tới "vsys", "running-config firewall", "1 rule allow
duy nhất theo thứ tự XML" đều phải hiểu theo đúng ánh xạ dưới đây — **không đổi thứ tự ưu tiên
tier, không đổi điều kiện exact-scope, không đổi format export.**

## 0.1. Đối tượng kết nối

- Trường kết nối đổi từ **"Management IP firewall"** → **"Panorama IP"** (+ **API Key Panorama**).
- Thêm 2 trường bắt buộc/tùy chọn tùy tính năng:
  - **Device Group** (bắt buộc — thay thế hoàn toàn cho dropdown "VSYS" ở bản cũ) — danh sách
    lấy qua API `type=op`, lệnh `<show><devicegroups/></show>`, hoặc parse trực tiếp từ
    `/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name=...]`.
  - **Target Firewall (Serial)** — **tùy chọn**, chỉ bắt buộc khi dùng **Live Match**, **Zone
    awareness**, hoặc **Rule Hit Count (Policy Optimizer)** — 3 tính năng này chạy trên dataplane
    của 1 firewall cụ thể, Panorama chỉ đóng vai trò **proxy** (`target=<serial>` trong request).
    Không nhập Target → 3 tính năng này tự vô hiệu hóa, **im lặng**, đúng nguyên tắc "Continue"
    đã có sẵn (giống hệt cách zone-lookup tự vô hiệu khi không parse được XML ở bản gốc).

## 0.2. Cấu trúc config & phân cấp thừa kế Object (thay cho "shared trước, vsys đè sau")

Panorama phân cấp theo **Device Group hierarchy** (cây cha-con, lấy qua `<show><devicegroups/></show>`
hoặc mục `parent-dg` trong config readonly), cộng thêm tầng **Shared** ở gốc:

```
Shared (Panorama, gốc)
  └─ Device Group cha (vd "DG-ALL")
       └─ Device Group con (vd "DG-DATACENTER")
            └─ Device Group cháu (vd "DG-DC-HANOI")  ← DG đang thao tác
```

**Nguyên tắc override object theo tên (thay thế "shared trước, vsys đè sau" của bản Firewall)**:
object cùng tên → **DG càng gần DG đang thao tác (càng con) càng thắng**; nếu DG hiện tại không
định nghĩa → tìm lên DG cha, cha nữa, ..., cuối cùng tới Shared. Thứ tự nạp bắt buộc khi build
resolver: **Shared → DG gốc-nhất → ... → DG cha trực tiếp → DG hiện tại**, nạp entry sau ĐÈ entry
trước nếu trùng tên (im hệt cơ chế "vsys đè shared" bản cũ, chỉ thay 1 tầng vsys bằng N tầng DG).

Toàn bộ hàm `resolver.py`/`GroupResolver`/`ServiceResolver` (mọi tool) **không đổi logic resolve
member bên trong** (II.3/III.4/IV.2 giữ nguyên tuyệt đối) — chỉ đổi **nguồn nạp object ban đầu**
từ "1 vsys + shared" thành "chuỗi DG cha-con + shared" như trên.

## 0.3. Rulebase & thứ tự đánh giá rule (thay cho "1 danh sách rule theo thứ tự XML vsys")

Panorama không có 1 "running-config" rulebase phẳng như firewall — rule nằm rải ở nhiều vị trí,
và **thứ tự PAN-OS đánh giá thật trên firewall quản lý** (bắt buộc phải mô phỏng đúng thứ tự này
cho mọi logic dựa trên "rule đứng trước/đứng sau" — TOP1 "rule đầu tiên thỏa điều kiện", shadow-
check quét ngược lên rule index nhỏ hơn, thứ tự XML = thứ tự đánh giá) là:

```
1. Shared PRE-rulebase          (/config/shared/pre-rulebase/security/rules)
2. DG tổ tiên xa nhất → ... → DG cha trực tiếp → DG hiện tại, PRE-rulebase
   (mỗi DG: /config/devices/.../device-group/entry[@name=DG]/pre-rulebase/security/rules)
3. Rule cục bộ trên chính firewall (nếu có target + muốn tính; xem 0.6)
4. DG hiện tại → DG cha trực tiếp → ... → DG tổ tiên xa nhất, POST-rulebase
   (chiều NGƯỢC LẠI so với PRE — con đánh giá trước cha ở post-rulebase)
5. Shared POST-rulebase         (/config/shared/post-rulebase/security/rules)
6. Default rule (intrazone-default / interzone-default)
```

**Bắt buộc**: mọi nơi trong Phần II/III/IV nói "rule_infos giữ đúng thứ tự XML = thứ tự PAN-OS
đánh giá" nay phải hiểu là **danh sách rule_infos được LẮP RÁP theo đúng 6 bước trên** (nối các
đoạn theo thứ tự, giữ nguyên thứ tự nội bộ trong từng đoạn), rồi mọi thuật toán tier/shadow/audit
chạy y hệt bản gốc trên danh sách đã lắp ráp này — **không đổi 1 dòng logic tier/shadow**.

**NAT Rule** dùng đúng cùng nguyên tắc lắp ráp thứ tự này với `pre-rulebase/nat/rules` và
`post-rulebase/nat/rules` (Shared + chuỗi DG), thay cho "1 vsys" ở bản cũ.

## 0.4. "Running config" & "Candidate config" trên Panorama

- **"Running config"** (bản gốc dùng làm nguồn "đã allow thật") → trên Panorama là **config đã
  commit vào Panorama** (`action=show`), **CHƯA CHẮC đã push xuống firewall thật**. Đây vẫn là
  nguồn duy nhất dùng cho toàn bộ thuật toán LOCAL (TOP1-4, shadow-check, audit) — giữ nguyên vai
  trò "sole authority" như II.5/IV mô tả, chỉ đổi nguồn API.
- **"Candidate config"** (`action=get`, toàn bộ cây gộp cả thay đổi Panorama chưa commit) — vai
  trò y hệt bản gốc (II.5 overlay tham khảo, IV Import/Delete) — chỉ đổi xpath sang cấu trúc DG.
- **Cảnh báo bổ sung bắt buộc** (không có ở bản Firewall gốc): Panorama có **2 tầng commit** —
  "Commit to Panorama" rồi mới "Commit and Push" xuống thiết bị. Mọi cảnh báo cố định kiểu
  *"Các thay đổi trên CHỈ nằm ở Candidate Config (chưa commit)..."* (IV.4 bước 5) ở bản Panorama
  phải nói rõ **2 bước**: *"...chưa commit vào Panorama, và dù có commit vào Panorama cũng CHƯA
  tự động đẩy xuống firewall — cần Commit and Push riêng."* `delete_rule_candidate` (IV) chỉ xoá
  trên **Candidate Config của Panorama**, xpath trỏ vào đúng vị trí DG + pre/post-rulebase của
  rule đó — không commit, không push, giữ nguyên nguyên tắc D6.

## 0.5. Live Match (Test Policy Match) — bắt buộc `target`

`test security-policy-match` chạy trên **dataplane firewall**, Panorama chỉ forward request —
mọi lời gọi API này (II.2.4) bắt buộc thêm `target=<serial firewall>` (lấy từ trường "Target
Firewall" ở 0.1) và `vsys=<vsys tương ứng trên chính firewall đó>` (1 firewall có thể có nhiều
vsys; DG chỉ ánh xạ gần đúng, KHÔNG thay thế vsys thật). Không có Target → tier LIVE_MATCH tự bỏ
qua (rơi thẳng xuống local), **im lặng**, không báo lỗi — đúng tinh thần "delegate hoàn toàn cho
firewall, không đoán bừa" (II.2.4) mở rộng thêm điều kiện tiên quyết "phải biết đoán hộ ai".
Toàn bộ luật còn lại của II.2.4 (range test 2 đầu mút, nhiều rule khác nhau → None, lỗi → None,
LUÔN LUÔN action_level='none' khi LIVE_MATCH...) **giữ nguyên tuyệt đối**.

## 0.6. Zone awareness — nguồn dữ liệu đổi từ "Interface/Zone trong vsys" sang "Template"

Interface/Zone trên Panorama không nằm trong Device Group — nằm trong **Template** (hoặc
Template Stack) được gắn cho firewall. Vì 1 Device Group có thể ứng với nhiều firewall dùng
Template khác nhau, `build_zone_lookup()` (II.6) **bắt buộc cần Target Firewall** để biết dùng
Template nào: lấy Template Stack gắn với serial đó (`<show><template-stack>...` hoặc suy ra từ
`/config/devices/entry[@name=serial]`), rồi parse Interface+Zone từ đúng Template đó bằng nguyên
văn logic `parse_interface_subnets`/`parse_zones` của bản gốc (kể cả gotcha `layer3/ip` vs `ip`
trực tiếp — không đổi). Không có Target → `zone_lookup` rỗng → tính năng Zone tự vô hiệu, đúng
hành vi "degrade im lặng" đã có sẵn ở bản gốc (không phải tính năng mới, chỉ thêm 1 điều kiện
tiên quyết).

## 0.7. Rule Hit Count / Policy Optimizer — bắt buộc `target`, tính theo TỪNG firewall

`show rule-hit-count` là dữ liệu **runtime của từng firewall**, không tồn tại ở tầng Panorama.
`fetch_rule_hit_count()` (IV.6/II) bắt buộc `target=<serial>`. Vì 1 rule Device-Group có thể được
nhiều firewall cùng dùng (mỗi firewall có hit-count riêng), khi có Target: lấy hit-count của
ĐÚNG firewall đó cho các rule áp dụng lên nó (pre + local + post theo đúng thứ tự 0.3); không có
Target → `hit_stats = {}` (API lỗi/không hỗ trợ) đúng hành vi D10 gốc → nhánh UNUSED tự tắt,
nhánh UNREACHABLE (không phụ thuộc hit-count) **vẫn chạy bình thường** — không đổi.

## 0.8. Danh sách API/xpath tham chiếu (map nhanh Firewall → Panorama)

| Việc cần làm | Firewall standalone (bản gốc) | Panorama (bản này) |
|---|---|---|
| Lấy running-config | `action=show`, xpath gốc `/config` | `action=show`, xpath gốc `/config` trên Panorama (chứa Shared + mọi Device Group) |
| Lấy candidate-config | `action=get`, xpath gốc `/config` | Tương tự, trên Panorama |
| Object Shared | `/config/shared/address...` (vsys global) | `/config/shared/address...` (Panorama-level) |
| Object theo vùng | `/config/devices/.../vsys/entry[@name=X]/address...` | `/config/devices/.../device-group/entry[@name=DG]/address...` (lặp theo chuỗi DG cha-con, 0.2) |
| Security Rule | `/config/devices/.../vsys/entry[@name=X]/rulebase/security/rules` | `.../device-group/entry[@name=DG]/pre-rulebase/security/rules` **và** `.../post-rulebase/security/rules`, cộng `/config/shared/pre-rulebase|post-rulebase/security/rules` (lắp ráp theo 0.3) |
| NAT Rule | `.../vsys/entry[@name=X]/rulebase/nat/rules` | Tương tự Security Rule, đổi `security` → `nat` |
| Danh sách "vùng" để chọn | `get_vsys_list()` | `<show><devicegroups/></show>` (op command) hoặc liệt kê `/config/devices/.../device-group/entry/@name` |
| Test Policy Match | `type=op`, không cần `target` | `type=op`, **bắt buộc `target=<serial>`** + `vsys=<vsys thật trên firewall đó>` (0.5) |
| Rule Hit Count | `type=op`, không cần `target` | `type=op`, **bắt buộc `target=<serial>`** (0.7) |
| Xoá rule candidate | xpath `.../vsys/entry[@name=X]/rulebase/security/rules/entry[@name=rule]` | xpath `.../device-group/entry[@name=DG]/pre-rulebase\|post-rulebase/security/rules/entry[@name=rule]` (đúng vị trí rule đang nằm — pre hay post) hoặc `/config/shared/...` nếu rule là Shared |
| Interface/Zone | `/config/devices/.../vsys/entry[@name=X]/import/network/interface` + `.../zone` trong vsys | Nằm trong **Template** gắn với Target Firewall (0.6), không nằm trong Device Group |

---

# PHẦN I — TỔNG QUAN SUITE (kiến trúc ghép 3 tool)

## I.1. Tóm tắt 1 phút

| | |
|---|---|
| **Tab "CHECK RULE"** | Tool #1 — kiểm tra 1 **request kết nối mới** (Source/Dest/Port) đã được rule Panorama nào (Shared/DG, pre hoặc post-rulebase) cho phép chưa; phát hiện object/service đã có sẵn để tránh tạo trùng; cảnh báo shadowing; đối chiếu candidate-config. |
| **Tab "CHECK IP"** | Tool #2 — tra cứu **Security Rule + NAT Rule** (Shared + Device Group, cả pre lẫn post-rulebase) liên quan tới 1 danh sách IP cụ thể (EXACT-HOST ONLY); đối chiếu File Log; xuất Excel/CSV rich-text. |
| **Tab "CHECK AUDIT"** | Tool #3 — audit "sức khỏe" toàn bộ rulebase của 1 Device Group (kể cả Shared + chuỗi DG cha áp xuống): **Shadow Rules**, **Disabled**, **Overly Permissive**; xoá rule trên **Candidate Config Panorama, không commit, không push**. |
| **Nguyên tắc cốt lõi** | 3 tool **hoàn toàn độc lập về code, namespace, output, log** — giữ nguyên như bản gốc. |
| **3 hình thái output mỗi lần bàn giao** | (1) File/package cấu phần đã sửa. (2) 1 file `.py` duy nhất (`PaloPANORAMA_single.py`, sinh bởi `tools/build_panorama_single.py`). (3) File `.md` này: cập nhật mục **TÌNH TRẠNG HIỆN TẠI** + thêm entry **XIV**. (4) Mở rộng `testlab/` để chốt lại thay đổi. Chi tiết 7 bước bắt buộc: **V.4.1**. |

## I.2. Cấu trúc thư mục (cập nhật 2026-10-20)

```
PaloPANORAMA/
├── PaloPANORAMA_single.py       <-- SẢN PHẨM CHÍNH DUY NHẤT (bản gộp 1 file) — KHÔNG sửa tay
├── PaloPANORAMA_single.md       <-- Tài liệu này (nguồn chân lý duy nhất)
├── tools/build_panorama_single.py  <-- Sinh lại bản gộp; `--check` để phát hiện lệch (exit 1)
│
├── check_rule_pan/              <-- Tool #1 CHECK RULE (luật: Phần II; hạ tầng: PHẦN 0)
│   ├── core.py                  # parse config Panorama, chuỗi DG, lắp ráp rulebase 6 bước, Template/Zone
│   ├── resolver.py  index.py  request.py        # THUẦN nghiệp vụ — y nguyên bản standalone
│   ├── matcher.py               # engine phân loại tier + Live Match (thêm target_serial)
│   ├── exporter.py              # xuất Excel (thêm cột "Vi tri Rule" ở vị trí 2)
│   └── gui.py                   # tab "CHECK RULE": Panorama IP + Device Group + Target Firewall
│
├── check_ip_pan/                <-- Tool #2 CHECK IP (luật: Phần III)
│   ├── core.py  resolver_engine.py  matching_engine.py
│   ├── pan_api.py               # đọc object/rule theo chuỗi DG + lắp ráp NAT theo pre/post-rulebase
│   ├── excel_export.py          # Excel/CSV rich-text + bản gộp 1 file 2 sheet
│   └── gui.py                   # tab "CHECK IP"
│
├── check_audit_pan/             <-- Tool #3 CHECK AUDIT (luật: Phần IV)
│   ├── core.py  resolver.py  detectors.py  excel_io.py
│   ├── pan_api.py               # hit-count (cần target) + lệnh ghi CANDIDATE theo xpath của DG
│   └── gui.py                   # tab "CHECK AUDIT"
│
├── tests/                       <-- Bộ test chung: python -m unittest discover -s tests
└── testlab/                     <-- MÔI TRƯỜNG CHẠY THỬ: Panorama giả lập (xem PHẦN VI)
    ├── mock_panorama_api.py     # Panorama giả lập HTTPS; từ chối op-command thiếu `target`
    ├── fixtures/*.xml           # running + candidate: 3 DG lồng nhau, Template/Stack, 13 rule + 2 NAT
    ├── samples/                 # file input mẫu (Request .xlsx/.csv, danh sách IP, File Log)
    ├── make_samples.py  run_all_features.py     # nghiệm thu 1 lệnh: --auto -> 68/68 PASS, exit 0/1
    └── README.md                # hướng dẫn mở GUI thật trỏ vào Panorama giả lập
```

3 package đặt tên có hậu tố `_pan` và **bản gộp nhúng đúng TÊN THẬT** đó (không đổi thành
`check_rule`) — nhờ vậy stack trace chỉ đúng module, và không lẫn với repo bản Firewall standalone.

## I.3–I.8

**Phần kiến trúc còn lại (lý do không gộp phẳng, quy tắc relative import, kỹ thuật đóng gói file
single qua zip+base64+MetaPathFinder, cách chạy dev, output/log riêng từng tool, sơ đồ khởi động
Tkinter Notebook) — **giữ nguyên 100% không đổi** so với bản Firewall standalone, vì đây là kiến
trúc GUI/đóng gói Python, hoàn toàn độc lập với việc nguồn dữ liệu là Firewall hay Panorama.
Tham chiếu lại nguyên văn nội dung I.2-I.8 của tài liệu gốc; chỉ 1 điểm đổi chữ: mọi chỗ ghi
**"Management IP firewall"** trên GUI đổi nhãn thành **"Panorama IP"**, và mọi chỗ có dropdown
**"VSYS"** đổi thành dropdown **"Device Group"** (populate qua 0.8), thêm ô **"Target Firewall
(Serial) - tùy chọn"** cạnh đó cho 3 tính năng cần target (0.1).

---

# PHẦN II — TOOL "CHECK RULE" (tool #1): luật vận hành đầy đủ

## II.0. Tóm tắt

**CHECK RULE** kiểm tra 1 danh sách "request" (Source IP, Dest IP, Port) so với rulebase Panorama
đang chạy thật (Shared + Device Group đang chọn, cả pre lẫn post-rulebase, lắp ráp đúng thứ tự
đánh giá theo 0.3), để trả lời: *"traffic này đã được rule nào cho phép chưa? Nếu chưa, cần tạo
rule mới hay chỉ cần bổ sung Source/Dest/Port vào 1 rule có sẵn?"*. Input: file Excel/CSV hoặc
nhập tay. Output: file Excel tô màu theo tier (xanh lá = đã đủ, cam = cần bổ sung, đỏ = chưa có
gì, xanh dương = same-subnet, tím = thiếu Zone) — **không đổi 1 quy tắc màu/tier nào**.

2 chế độ:
- **Online (Live Match)**: gọi API `test security-policy-match` qua Panorama với `target=<serial
  firewall>` bắt buộc (0.5) — đáng tin cậy tuyệt đối, y hệt nguyên tắc gốc.
- **Offline (Local)**: tự dựng lại logic matching dựa trên config XML lắp ráp theo 0.2/0.3.

## II.1. Data flow tổng quát (khi bấm "Check")

```
1. Load config
   → core.fetch_panorama_config_xml() (API, action=show, toàn bộ /config Panorama)
   → core.load_pan_config_from_xml_string() → cfg
   → core.resolve_devicegroup_chain(cfg, dg_name) → devicegroup_chain (Shared → ... → DG cha → DG hiện tại), theo 0.2
   → core.assemble_rule_infos_panorama(cfg, dg_name) → danh sách rule đã lắp ráp đúng thứ tự 6 bước ở 0.3
   → resolver.GroupResolver(cfg, devicegroup_chain) + resolver.ServiceResolver(cfg, devicegroup_chain)
   → index.build_device_index(cfg, resolver, svc_resolver) → idx
   → matcher.build_rule_infos(assembled_rules, resolver, svc_resolver) → rule_infos
   → (chỉ nếu có Target Firewall) index.build_zone_lookup(template_of_target, ...) → zone_lookup — xem 0.6
   → (song song, tách biệt) core.fetch_candidate_config_xml() → parse (đúng cấu trúc DG) → diff →
     candidate_rule_infos / candidate_idx riêng

2. Đọc request → request.parse_request_file(path) / build_manual_request(rows) → List[RequestRow]

3. Với MỖI RequestRow (đa luồng, ThreadPoolExecutor):
   → matcher.classify_row(row, rule_infos, idx, ..., zone_lookup=zone_lookup, target_serial=target_or_None) → RowResult
     (LIVE_MATCH bên trong classify_row: nếu target_serial is None → bỏ qua tier này ngay, 0.5)
   → matcher.apply_candidate_overlay(res, row, candidate_rule_infos, candidate_idx)
     (bỏ qua nếu res.tier == 'LIVE_MATCH')

4. exporter.export_results(headers, results, out_path) → file Excel
```

## II.2. Thứ tự ưu tiên tier trong `classify_row()` — GIỮ NGUYÊN 100%

```
0. INVALID       — thiếu Source/Dest/Port hợp lệ trong dòng input
1. LIVE_MATCH    — (chỉ khi có Target Firewall + API Key hợp lệ) gọi Test Policy Match qua Panorama
2. SAME_SUBNET   — Source & Dest cùng 1 subnet (mặc định /24) → traffic không qua Firewall
3. TOP1          — FULL MATCH tuyệt đối: 1 rule allow (bất kể Shared/DG, pre/post) có
                   Source/Dest/Service cover CHÍNH XÁC (exact) toàn bộ input
4. TOP1.1        — Source+Dest khớp CHÍNH XÁC 1:1, chỉ thiếu Port → "+ ADD PORT"
5. TOP2          — Dest khớp CHÍNH XÁC 1:1 + Port đủ, Source còn thiếu → "+ ADD SOURCE"
6. TOP3          — đối xứng TOP2: Source khớp CHÍNH XÁC 1:1 + Port đủ, Dest thiếu → "+ ADD DEST"
7. TOP4          — không tier nào ở trên đủ điều kiện AN TOÀN → rule "GẦN ĐÚNG NHẤT" tham khảo,
                   hoặc "Chưa có Rule - cần tạo mới"
```

"Rule đầu tiên theo thứ tự list" ở TOP1/`_scan_all_tiers` (0.3) nay là **rule đầu tiên trong danh
sách đã lắp ráp Shared-PRE → DG-chain-PRE → (local, nếu tính) → DG-chain-POST → Shared-POST** —
không phải rule đầu tiên trong 1 vsys phẳng. Mọi điều kiện dưới đây (II.2.1 → II.2.4) **áp dụng
y hệt bản gốc**, chỉ chạy trên rule_infos đã lắp ráp theo 0.3 thay vì rule_infos của 1 vsys.

### II.2.1–II.2.3 — Nguyên tắc exact-scope, loại rule quá rộng, 3 tầng TOP4

**Giữ nguyên tuyệt đối, không đổi 1 điều kiện nào**: `_is_exactly_scoped()` dựa trên
`total_address_count()`; loại rule `Service=any`, loại `icmp/portless + cả 3 field=any`, loại
`Source và Dest cùng any`; 3 tầng TOP4 (`near_top2` > `near_top3` > `generic`) với tie-break
`(scope_size tăng dần, số Zone còn thiếu tăng dần — chỉ tính được khi có `zone_lookup` từ 0.6,
frac giảm dần)`. Object/group dùng trong các phép so sánh này được resolve qua chuỗi thừa kế DG
(0.2) thay vì 1 vsys — bản thân phép so sánh (exact/wide/is_any) không đổi.

### II.2.4. `try_live_match()` — bắt buộc `target`, còn lại giữ nguyên

Điều kiện tiên quyết mới (0.5): chỉ chạy khi có **Target Firewall (serial)** hợp lệ; thiếu →
LIVE_MATCH tự bỏ qua ngay từ đầu `classify_row()` (không phải lỗi, không log cảnh báo ồn ào — 1
dòng log mức debug là đủ), rơi thẳng xuống local. Khi có target: mọi luật còn lại **giữ nguyên
100%** — test cả 2 đầu mút cho range, 1 điểm cho cidr, nhiều rule khác nhau → None, lỗi/không xác
nhận/action≠allow → None, không bao giờ đoán bừa. **Luật hiển thị bắt buộc giữ nguyên**: khi
`tier == 'LIVE_MATCH'`, `_compute_action_level()` LUÔN trả `'none'` (FULL MATCH), tuyệt đối không
phụ thuộc `source_report`/`dest_report`, kể cả khi đối chiếu tên rule cục bộ thất bại.

## II.3. `resolver.py` — cách "giải" 1 tên object/group ra tập IP/Port

**Không đổi 1 dòng logic bên trong** (`ResolvedAddr`, `covers_range_exact/wide/wide_confirmed`,
`has_exact_member`, `total_address_count`, `ResolvedService`, cache + lock chống race, phát hiện
circular reference, `_PREDEFINED_SERVICES`). Thay đổi DUY NHẤT: `GroupResolver(cfg)` /
`ServiceResolver(cfg)` nay nhận thêm `devicegroup_chain` (danh sách object-source theo thứ tự
Shared → ... → DG hiện tại, từ 0.2) thay vì nhận `cfg` của 1 vsys đơn — khi resolve 1 tên, tra
theo thứ tự chain đó, entry ở DG gần hơn ghi đè entry cùng tên ở DG xa hơn/Shared.

## II.4. Cảnh báo che khuất (shadowing) — `_find_shadowing_rule()`

**Không đổi thuật toán**: quét ngược lên các rule có "index" nhỏ hơn (đứng trước) trong danh sách
đã lắp ráp (0.3) tìm rule deny/drop/reset cũng khớp traffic. Vì rulebase Panorama trải qua nhiều
đoạn (Shared-PRE/DG-chain-PRE/DG-chain-POST/Shared-POST), "index nhỏ hơn" nghĩa là **đứng trước
trong danh sách đã lắp ráp**, không phải đứng trước trong 1 đoạn riêng lẻ — 1 rule Shared-PRE
luôn có index nhỏ hơn mọi rule DG-PRE, luôn có thể che chúng; ngược lại rule Shared-POST luôn có
index lớn nhất, không thể che rule nào đứng trước nó. Dùng đúng `_side_all_for_shadow()`/
`_ports_covered_for_shadow()` (có xét `is_any`) như bản gốc.

## II.5. Candidate-config overlay — `apply_candidate_overlay()`

**Không đổi logic**: candidate-config Panorama (`action=get`) trả về toàn cây gộp cả thay đổi
chưa commit; `diff_candidate_config()` lọc xuống rule/object/group thật sự mới/thay đổi so với
running (nay so trên toàn bộ cấu trúc Shared+DG-chain, không phải 1 vsys). `apply_candidate_
overlay()` vẫn chỉ sửa report của `RowResult`, bỏ qua khi tier là LIVE_MATCH/SAME_SUBNET/INVALID,
`is_any` vẫn được coi là "đã cover" ở lớp này (khác 3 quy tắc II.2.2, y hệt bản gốc). **Ghi chú
bổ sung khi hiển thị**: vì Panorama có thêm bước "Commit and Push" (0.4), overlay này chỉ phản
ánh "nếu Panorama commit" — chưa chắc đã push xuống firewall; nhãn hiển thị trên Excel nên giữ
nguyên như bản gốc (không đổi cột/màu), chỉ thêm ghi chú này vào phần README/help nếu tool có mục
giải thích, KHÔNG đổi cấu trúc file Excel.

## II.6. `index.py` — tra cứu "đã có sẵn object/group đại diện chưa"

**Không đổi nguyên tắc "exact-only"** cho IP lẫn Port. `find_existing_ip_representation`,
`find_best_covering_group`, `find_existing_service_representation` chạy trên `idx` được build từ
object đã resolve qua chuỗi DG (0.2) — bản thân thuật toán chọn "đại diện tốt nhất" không đổi.
`build_zone_lookup()`/`resolve_zone_for_ip()`: nguồn Interface/Zone đổi sang Template của Target
Firewall (0.6); thuật toán longest-prefix-match nội bộ **không đổi**; không có Target → trả rỗng,
tính năng tự vô hiệu — đúng hành vi gốc.

## II.7. Kiến trúc thực thi `classify_row()` — quét 1 lần (`_scan_all_tiers`)

**Không đổi 1 dòng** — toàn bộ nội dung II.7 gốc (quét 1 lần thay vì 5 lần, TOP1 break sớm, dùng
chung `dst_covered_cnt`/`src_covered_cnt`, differential test 5.000 kịch bản, benchmark ~1.46 lần
nhanh hơn) áp dụng y hệt trên `rule_infos` đã lắp ráp theo 0.3 — việc lắp ráp chỉ ảnh hưởng ĐẦU
VÀO (danh sách rule + thứ tự), không ảnh hưởng thuật toán quét.

## II.8. Checklist khi sửa code CHECK RULE

1. CHỈ sửa ở đúng 1 module. 2. Build lại single. 3. `py_compile`. 4. Chạy lại 4 kịch bản hồi quy
gốc (II.2.2) **cộng thêm** 2 kịch bản mới bắt buộc cho bản Panorama: (a) rule Shared-PRE che rule
DG-POST cùng traffic → phải báo shadow đúng; (b) không nhập Target Firewall → LIVE_MATCH/Zone tự
tắt, không lỗi, không crash. 5. Cập nhật mục XIV trong cùng lần sửa.

---

# PHẦN III — TOOL "CHECK IP" (tool #2): luật vận hành đầy đủ

## III.0. Tóm tắt & mục tiêu

**Không đổi mục tiêu nghiệp vụ**: (1) Tra cứu Security Policy theo danh sách IP (EXACT-HOST
ONLY, resolve toàn bộ Address Object/Group, không match theo tên, không coi subnet rộng là
match). (2) Đối chiếu File Log, mô phỏng Test Policy Match. (3) Xuất Excel rich-text theo template
gốc. (4) Export bảng NAT riêng (Full/Search). Phạm vi tìm kiếm nay là **Shared + Device Group
đang chọn (cả pre lẫn post-rulebase)** thay vì "1 vsys" — Test Policy Match mô phỏng (III.6, chạy
OFFLINE, không gọi API thật) dùng đúng thứ tự lắp ráp 0.3.

## III.1. Kiến trúc module & data flow

**Không đổi bảng module** (`core.py`/`pan_api.py`/`resolver_engine.py`/`matching_engine.py`/
`excel_export.py`/`gui.py`). Thay đổi trong `pan_api.py`: `fetch_running_config()` gọi trên
Panorama trả về toàn cây (Shared + mọi DG); hàm mới `select_devicegroup_scope(cfg, dg_name)` cắt
ra đúng phần cần dùng (chuỗi DG cha-con theo 0.2 cho object, lắp ráp pre/post theo 0.3 cho rule)
— tương đương vai trò "chọn VSYS" ở bản gốc, chạy NGAY SAU Connect, TRƯỚC khi vào màn hình chính.

## III.2. Giao diện — 4 mục (đổi nhãn, không đổi hành vi)

**Mục 1**: đổi `Management IP` → **`Panorama IP`**; giữ nguyên API Key/checkbox SSL; dropdown
**`VSYS`** → **`Device Group`** (populate sau Connect qua 0.8); thêm ô **`Target Firewall
(Serial) - không bắt buộc`** — chỉ ảnh hưởng tới Test Policy Match thật nếu tool này có gọi (mặc
định CHECK IP mô phỏng offline, KHÔNG gọi API thật — xem III.6 — nên trường này chỉ dùng nếu sau
này bổ sung Live verify; hiện tại để trống không ảnh hưởng gì).

**Mục 2/3/4**: **không đổi hành vi** — danh sách IP cần tìm (hỗ trợ range), File Log đối chiếu,
Export bảng NAT Full/Search, quy tắc validate 3-điều-kiện khi bấm Search — giữ nguyên nguyên văn
III.2 gốc.

## III.3. Kết nối & Parse cấu hình

`PanApiClient(host, api_key, verify_ssl, timeout)` nay trỏ **Panorama IP**; `test_connection()`
lấy hostname Panorama; `fetch_running_config()` vẫn gọi **1 lần duy nhất** lấy toàn bộ config
Panorama (thay vì 1 vsys firewall) — dùng chung cho mọi tính năng, cache lại, không gọi lại khi
đổi Device Group (chỉ cắt lại phần dùng, theo III.1). **Parse config**: đọc Shared + toàn bộ
Device Group theo chuỗi cha-con của DG đang chọn (0.2), nạp theo đúng thứ tự Shared trước, DG xa
đè bởi DG gần hơn — thay cho "shared trước, vsys đè sau". Address Object 3 kiểu / Address Group
static-dynamic / Service Group `<members>` / Security Rule đọc đủ field / NAT Rule + 2 chiều
Translation — **parse logic không đổi 1 dòng**, chỉ đổi xpath nguồn (0.8) và nay đọc từ CẢ
`pre-rulebase` lẫn `post-rulebase` (2 xpath riêng, gộp lại) thay vì 1 `rulebase` phẳng.

## III.4. `GroupResolver` — Engine resolve Object/Group

**Không đổi 1 dòng logic `_compute()`** (thứ tự ưu tiên literal → ip-netmask host-only →
ip-range luôn exact → fqdn unresolved → static group đệ quy → dynamic group filter tag; cache
double-checked locking; chống circular bằng `visiting`). Nguồn object nạp vào resolver đổi theo
0.2 (chuỗi DG cha-con + Shared) thay vì "1 vsys + shared".

## III.5. Search chính (mục 2 GUI) — EXACT-HOST ONLY

**Không đổi**: `build_index()` gom toàn bộ tên tham chiếu trong Source/Destination của MỌI rule
trong phạm vi đã chọn (nay là Shared+DG-chain, cả pre lẫn post — thay vì 1 vsys), resolve song
song, build `IndexData`. `search_ips()` tra O(1) + quét tuyến tính range — không đổi. Kết quả
xuất Excel: 1 rule = 1 dòng, cột "Matched Side" — không đổi, chỉ nay rule có thể đến từ Shared
hoặc bất kỳ DG nào trong chuỗi, pre hoặc post; nên hiển thị thêm rõ **nguồn rule** (Shared-PRE /
`<DG>`-PRE / `<DG>`-POST / Shared-POST) — đây là **field mới bắt buộc thêm vào output** vì không
còn "chỉ 1 vsys" để ngầm hiểu, khác bản gốc chỉ có 1 nguồn duy nhất.

## III.6. Đối chiếu File Log — mô phỏng "Test Policy Match"

**Không đổi thuật toán** `find_first_allow_rule_match` (lọc `ordered_allow_rules` giữ đúng thứ
tự đánh giá, duyệt top-down, dừng ở rule đầu tiên khớp đủ 3 điều kiện, fix `application-default`+
portless không coi là khớp khi Log có Port cụ thể). **`ordered_allow_rules` nay là danh sách đã
lắp ráp theo 0.3** (Shared-PRE → DG-chain-PRE → DG-chain-POST → Shared-POST; KHÔNG tính rule cục
bộ trên firewall vì tool này không có Target Firewall — xem giới hạn mới ở III.10). Giới hạn "File
Log không có Zone/Application thật" giữ nguyên.

## III.7. Export bảng NAT (mục 4 GUI)

**Không đổi cột xuất, không đổi 2 tham số `highlight_ips`/`filter_ips`, không đổi cách lọc 4
trường, không đổi cách đặt tên file**. Nguồn NAT Rule đổi sang lắp ráp `pre-rulebase/nat/rules` +
`post-rulebase/nat/rules` của Shared + chuỗi DG (0.3, áp dụng tương tự Security Rule) thay vì 1
vsys. Cột **thêm mới bắt buộc** (giống III.5): "Nguồn Rule" (Shared-PRE/`<DG>`-PRE/`<DG>`-POST/
Shared-POST) — vì bản Panorama không còn 1 vsys duy nhất để ngầm định.

## III.8. Excel Template & Export — Security Rule

**Không đổi template, không đổi style, không đổi rich-text (in đậm tên object, xanh lá khi trùng
input, đỏ khi khác, group chỉ hiện member khớp...)**. Cột cuối cùng khi xuất **thêm 1 cột mới**
ngay sau "Name Rule": **"Vi tri Rule"** (giá trị: Shared-PRE / `<Device Group>`-PRE /
`<Device Group>`-POST / Shared-POST) — bắt buộc thêm vì đây là thông tin cần thiết để admin biết
sửa rule ở đâu trên Panorama, không tồn tại ở bản Firewall (chỉ 1 rulebase phẳng nên không cần).
Toàn bộ cột còn lại (UUID, Zone, Application, Action, Profile, Log Setting, Schedule, Description,
Tag, Disabled, Target, HIP, Source User) **giữ nguyên thứ tự và nội dung**.

## III.9. `log.txt` & Error Handling

**Không đổi**.

## III.10. Giới hạn đã biết (CHECK IP, bản Panorama)

1. Test Policy Match mô phỏng không xét Zone/Application thật (giữ nguyên giới hạn gốc).
2. **Mới**: mô phỏng offline **không tính rule cục bộ trên chính firewall quản lý** (rule cấu
   hình trực tiếp trên thiết bị, ngoài tầm quản lý Panorama) — chỉ tính Shared + Device Group;
   nếu firewall có rule cục bộ chen giữa pre và post-rulebase (0.3 bước 3), kết quả offline có
   thể khác thực tế ở đúng vị trí đó. Không có cách khắc phục offline — muốn chính xác tuyệt đối
   phải dùng Live Match ở tool CHECK RULE (Phần II) với Target Firewall.
3. FQDN address object không resolve được ra IP — loại khỏi match (giữ nguyên).
4. NAT export: xem giới hạn riêng III.7. Scope nay là Panorama (đã bỏ giới hạn "chỉ 1 Firewall
   độc lập" của bản gốc, đổi thành giới hạn mới ở mục 2 phía trên).

---

# PHẦN IV — TOOL "CHECK AUDIT" (tool #3): luật vận hành đầy đủ

## IV.0. Tóm tắt & mục tiêu

**Không đổi mục tiêu**: audit "sức khỏe" rulebase — Shadow Rules, Disabled Rules, Overly
Permissive Rules — trên phạm vi **Shared + Device Group đang chọn (pre và post-rulebase, lắp ráp
theo 0.3)** thay vì "1 vsys firewall". Hỗ trợ xoá rule trên **Candidate Config của Panorama**
(không commit, không push — 0.4). Giải lập Assessment vẫn dựa trên **superset** (R1 rộng hơn
hoặc bằng R2 là che được), không đổi.

## IV.1. Kiến trúc module & data flow — vẫn 7 file, đổi nội dung `pan_api.py`/`core.py`

| File | Thay đổi so với bản Firewall gốc |
|---|---|
| `core.py` | Thêm hằng số `DEVICEGROUP_CHAIN` (kết quả `resolve_devicegroup_chain`, 0.2), giữ nguyên `OUTPUT_DIR`/`LOG_PATH`/`UNUSED_RULE_THRESHOLD_DAYS=30`/toàn bộ dataclass/exceptions/IP utils/`build_service_info`. |
| `pan_api.py` | `fetch_running_config()` trỏ Panorama; **`delete_rule_candidate`** nay nhận thêm tham số `devicegroup` + `rulebase` (`pre`/`post`/`shared-pre`/`shared-post`) để dựng đúng xpath (0.8) — vẫn `type=config&action=delete`, KHÔNG commit, KHÔNG push; **`fetch_rule_hit_count`** bắt buộc `target=<serial>` (0.7), thiếu target → trả `{}` luôn (không gọi API), coi như "API không hỗ trợ" theo đúng D10; thêm `get_devicegroup_list()`/`resolve_devicegroup_chain()`; `parse_security_rules()` nay **gọi 2 lần** (pre-rulebase + post-rulebase) cho mỗi phần tử trong chuỗi DG + Shared rồi lắp ráp theo đúng 6 bước 0.3, thay vì 1 lần cho 1 vsys. |
| `resolver.py` | Không đổi logic superset `covers_wide`/chống circular; nguồn nạp object đổi theo 0.2. |
| `detectors.py` | **Không đổi 1 dòng thuật toán** (IV.2 dưới đây) — chỉ chạy trên `rules` đã lắp ráp theo 0.3 và `hit_stats` theo 0.7. |
| `excel_io.py` | Thêm 1 cột bắt buộc **"Vi tri Rule"** (Shared-PRE/`<DG>`-PRE/`<DG>`-POST/Shared-POST) vào bộ 14 cột nền chung (nay 15 cột) — cần thiết để admin biết xoá/sửa ở đâu; `parse_import_file()` khi Import phải đọc lại đúng cột này để `delete_rule_candidate` dựng đúng xpath. Toàn bộ style/font/màu/format Port giữ nguyên. |
| `gui.py` | Đổi nhãn Khung 1: `Management IP` → `Panorama IP`, thêm dropdown `Device Group`, thêm ô `Target Firewall (Serial) - không bắt buộc, cần cho Rule Hit Count`. Khung 2/3/4/5 không đổi. |

## IV.2. Thuật toán từng detector (`detectors.py`) — GIỮ NGUYÊN 100%

### IV.2.1 `find_disabled_rules(rules)` — không đổi.

### IV.2.2 `find_overly_permissive_rules(rules)` — không đổi (6 tổ hợp literal `any`, tính cả
rule disabled, rule không có service nào → coi như Dest Port=any).

### IV.2.3 `find_shadow_rules(rules, resolver, svc_resolver, hit_stats, now)` — không đổi thuật
toán 5 điều kiện superset (from_zones/to_zones/source/destination/service, R1 disabled → bỏ
qua), không đổi cách gộp 2 nhánh UNREACHABLE+UNUSED thành 1 Finding, không đổi ngưỡng 30 ngày.
**Duy nhất khác biệt**: `rules` truyền vào là danh sách đã lắp ráp theo 0.3 — nghĩa là 1 rule
Shared-PRE giờ có thể là "R1 che khuất" cho 1 rule ở tận DG-POST cách xa nó trong cấu trúc thật,
điều này **đúng theo hành vi PAN-OS thật** (không phải lỗi mở rộng phạm vi, mà là mô phỏng đúng
hơn so với chỉ nhìn 1 vsys). `from_zones`/`to_zones` dùng để so superset **cần dữ liệu Template
của Target Firewall** giống 0.6 — không có Target → so sánh Zone luôn coi 2 bên "tương thích"
(fallback về hành vi cũ trước khi có Zone awareness, KHÔNG chặn audit chạy, chỉ giảm độ chính
xác của điều kiện 1/2 trong 5 điều kiện superset — cảnh báo rõ trong log khi thiếu Target).

> **SỬA 2026-09-02 audit #1 (lỗ hổng D9 còn sót):** `_find_unreachable_rules()` trước đây khoá `shadow` theo tên thuần `r2.name`, nay **đã sửa khoá theo `(r2.name, r2.vi_tri)`** đồng bộ với `_find_unused_rules` (vốn đã sửa ở bản 2026-09-02). Mọi tra cứu `unreachable_map` trong `find_shadow_rules` cũng đổi sang `(r.name, r.vi_tri)` + fallback tên thuần cho test cũ. Nếu không sửa, 2 rule cùng tên ở 2 DG khác nhau sẽ ghi đè nhau trong dict, dẫn tới gán sai `shadowed_by_rule_name` hoặc làm mất Finding — lỗi nằm ngay cạnh đoạn vừa sửa cho nhánh UNUSED nên dễ bỏ sót khi review diff.

## IV.3. Giao diện — 5 khung

**Khung 1**: đổi `Management IP` → `Panorama IP`; thêm dropdown **Device Group** (bắt buộc, thay
cho việc audit ngầm định "vsys hiện tại"); thêm ô **Target Firewall (Serial)** không bắt buộc
(ảnh hưởng Rule Hit Count + độ chính xác so Zone ở shadow-check, 0.7/IV.2.3). Khung 2/3/4/5 —
**không đổi**, chỉ Khung 4 (bảng kết quả) thêm 1 cột **"Vi tri Rule"** như IV.1.

## IV.4. Luồng Import → popup xác nhận (đã phân biệt hành động từ 2026-08-29)

**Quy tắc mới (IV.4 cập nhật):**
- **Shadow Rules có `hit_count==0` (UNUSED, 0 hits)** → khi Import **chỉ cho phép Disable** (không xóa thẳng).
  Gọi `disable_rule_candidate()` → `action=set` xpath `.../disabled` với `<disabled>yes</disabled>`, CANDIDATE only, không commit/push. Popup hiển thị **"Disable" (màu cam)**.
- **Disabled Rules** → khi Import **cho phép Delete** (xóa thẳng candidate). Gọi `delete_rule_candidate()` → `action=delete` xpath entry. Popup hiển thị **"Delete" (màu đỏ)**.
- **Overly Permissive Rules** → **chỉ Export**, Import bỏ qua hoàn toàn (log cảnh báo, không hiện trong popup) — D5 mới.

Trình tự D5/D6/D9 giữ nguyên, chỉ bước 4 tách nhánh: `disable_rule_candidate()` vs `delete_rule_candidate()` dựng xpath theo cột **"Vi tri Rule"** (0.8) — trỏ đúng `pre-rulebase`/`post-rulebase` của đúng Device Group hoặc Shared. `parse_import_file()` nay đọc thêm cột `Hit Count` (4-tuple) để xác định hit==0 chính xác, giữ tương thích file cũ không có cột (coi như 0). Bước 5 (cảnh báo cuối) **đổi nội dung theo 0.4 + báo cáo riêng**: `Disable OK: X / Delete OK: Y / Lỗi: Z`, nhấn mạnh 2 tầng commit (Panorama → Push), không chỉ 1 tầng như bản Firewall gốc.

## IV.5. Định dạng Export/Import — 15 cột (thêm 1 so với bản gốc)

Giữ nguyên toàn bộ 14 cột gốc + style (font Times New Roman 11, header teal-blue `FF0D7377`,
data trắng, viền `FFC9C9C9`, `same_action=False` → chữ Action đỏ đậm, TEXT format `@`, AutoFilter
+ freeze header, CSV `utf-8-sig`). **Thêm cột thứ 15 "Vi tri Rule"** ngay sau "Name Rule" (giá trị
Shared-PRE/`<DG>`-PRE/`<DG>`-POST/Shared-POST) — bắt buộc cho Import (IV.4). `parse_import_file()`
nay bắt buộc đủ 3 cột `Name Rule` + `Loại (Finding Type)` + `Vi tri Rule` (thiếu → raise lỗi rõ
ràng, giữ nguyên nguyên tắc validate nghiêm ngặt của bản gốc chỉ mở rộng thêm 1 cột bắt buộc).

## IV.6. `pan_api.py` — API rules bắt buộc (bản Panorama) — cập nhật 2026-09-02 sửa lỗ hổng D9

1. `delete_rule_candidate(panorama_ip, api_key, devicegroup, rulebase, rule_name, verify_ssl)` —
   KHÔNG request nào chứa `type=commit` — giữ nguyên. Dùng cho **Disabled Rules → Delete**.
2. `disable_rule_candidate(panorama_ip, api_key, devicegroup, rulebase, rule_name, verify_ssl)` — **mới từ 2026-08-29** cho **Shadow hit==0 → Disable**: `type=config&action=set&xpath=.../disabled&element=<disabled>yes</disabled>`, KHÔNG commit/push.
3. `fetch_rule_hit_count(panorama_ip, api_key, target_serial, verify_ssl, log_func) -> Dict[Tuple[str,str], RuleHitStat]` — **SỬA 2026-09-02 (lỗ hổng D9)**: trước đây trả `Dict[str, RuleHitStat]` khoá theo tên thuần, nay **bắt buộc khoá theo `(rule_name, vi_tri)`** với `vi_tri` ∈ {`Shared-PRE`/`Shared-POST`/`DG-PRE`/`DG-POST`} (IV.5) để phân biệt 2 rule cùng tên ở 2 Device Group khác nhau (Panorama cho phép trùng tên, khác standalone phẳng). Thiếu `target_serial` → `{}` degrade im lặng (0.7); lỗi API → log cảnh báo + `{}` best-effort (D10) — không đổi hành vi, chỉ đổi khoá. **SỬA 2026-10-20**: gọi **4 lệnh chi phí cố định** — Device Group (wildcard) `pre`/`post` **+ Shared** `pre`/`post`; nhánh `<shared>` là best-effort (Panorama từ chối → chỉ log cảnh báo, rule DG vẫn đủ hit-count). Response được suy `vi_tri` từ **chính cây XML trả về** (`device-group|shared` + `pre|post-rulebase`), không đoán theo tên. Mọi nơi gọi (detectors/`find_shadow_rules` và `gui._delete_worker`) đã rà soát cập nhật tra cứu theo khoá mới.
4. `fetch_current_rule_states(panorama_ip, api_key, verify_ssl, log_func) -> Optional[Dict[Tuple[str,str], dict]]` — **mới 2026-09-02 (IV.8)**: đọc **Candidate Config** (`action=get`, 4 lệnh cố định, xem IV.8) để xác minh tồn tại/trạng thái ngay trước khi ghi. Xem chi tiết IV.8.
5. `get_devicegroup_list()` / `resolve_devicegroup_chain(dg_name)` (thay `get_vsys_list()`) /
   `parse_security_rules()` gọi cho từng phần tử trong chuỗi + Shared, cả pre lẫn post, rồi lắp
   ráp theo 0.3 (thay `get_vsys_element()`/1-lần-parse cũ) / `parse_devicegroup_objects()` (thay
   `parse_vsys_objects()`, đọc theo chuỗi thừa kế 0.2).

## IV.7. Giới hạn đã biết (CHECK AUDIT, bản Panorama)

1. UNUSED phụ thuộc `show rule-hit-count` **và bắt buộc có Target Firewall** — không có Target →
   nhánh UNUSED tự tắt hoàn toàn (không phải "API không hỗ trợ" như bản gốc, mà là "chưa chọn
   thiết bị để hỏi"); nhánh UNREACHABLE vẫn chạy.
2. Overly Permissive chỉ nhận diện literal `any` (giữ nguyên).
3. Delete chỉ tác động Candidate Config **của Panorama**, không commit, không push — admin phải
   tự review + Commit + Commit-and-Push thủ công (mở rộng từ D6 gốc, xem 0.4).
4. Object FQDN/không resolve được → bỏ qua, không crash (giữ nguyên).
5. `same_action=False` chỉ là cờ cảnh báo (giữ nguyên).
6. **Mới**: so sánh Zone trong 5-điều-kiện-superset (IV.2.3) chỉ chính xác khi có Target Firewall
   (0.6); không có Target → điều kiện Zone fallback "luôn coi tương thích", có thể báo shadow ở
   trường hợp thực tế Zone khác nhau không thật sự che nhau — cảnh báo rõ trong log mỗi lần chạy
   audit thiếu Target.
7. **Mới**: audit không xét rule cục bộ cấu hình trực tiếp trên firewall (ngoài tầm Panorama) —
   giống giới hạn III.10 mục 2.

## IV.8 — Xác minh lại theo batch trước khi Disable/Delete (mới 2026-09-02, chi phí cố định, không đổi detector/format/xpath)

**Bối cảnh & lỗ hổng đã sửa:** `fetch_rule_hit_count()` trước 2026-09-02 trả `Dict[str, RuleHitStat]` khoá theo tên thuần, vi phạm D9 khi 2 Device Group khác nhau có rule trùng tên (Panorama cho phép, standalone không). Đã sửa thành `Dict[Tuple[str,str], RuleHitStat]` khoá `(rule_name, vi_tri)` — `vi_tri` tận dụng sẵn trong candidates tuple 6 phần tử `(name, loai, vi_tri, dg, rb, action)` (IV.4). Mọi dict/map trong tính năng mới này đều khoá theo `(rule_name, vi_tri)`, không khoá theo tên thuần.

**Mục tiêu:** giảm rủi ro config đổi giữa `T0` (lúc Check) và `T1` (lúc thực thi Disable/Delete), giống Prompt A nhưng phải xử lý đặc thù Panorama: rulebase lắp ráp 6 bước (0.3), `target_serial` OPTIONAL (0.1/0.7), candidates đã có `vi_tri`/`dg`/`rb`.

**Ràng buộc bắt buộc (không đổi):**
- D6: tuyệt đối không `type=commit`/`action=commit` trong toàn bộ xác minh — chỉ `action=get`/`action=op` (đọc).
- Đọc lại rule states dùng **Candidate Config** (`action=get`, không phải `action=show` Running Config) — ngoại lệ có chủ đích so với 0.4: cần trạng thái mới nhất kể cả thay đổi candidate chưa commit của người khác ngay trước khi ghi; Running Config vẫn là sole authority cho thuật toán LOCAL/Check.
- Chi phí cố định **4–5 API call/batch** (4 cho `fetch_current_rule_states` + 1 cho `fetch_rule_hit_count` nếu có `target_serial`), không phụ thuộc số rule hay số Device Group — có test đo đếm.

### IV.8.1 Chữ ký mới `gui.py`

```python
_delete_worker(self, candidates, mgmt_ip, api_key, verify_ssl, target_serial)
```
Thêm `target_serial: str` lấy đúng giá trị ô **Target Firewall (Serial)** trên GUI tại thời điểm bấm Xác nhận (có thể rỗng). Nơi gọi `_delete_worker` truyền thêm `self._target_serial`.

### IV.8.2 Batch xác minh ngay trước loop (chỉ 1 lần/batch, không gọi trong loop)

**a) Fresh Hit Stats (nếu có target):**
```python
if target_serial:
    fresh_hit_stats = fetch_rule_hit_count(mgmt_ip, api_key, target_serial, verify_ssl, log_func)
    # đã sửa D9 + audit #2: Dict[Tuple[str,str], RuleHitStat] khoá (rule_name, vi_tri)
    # SỬA 2026-09-02 audit: bỏ cmd sai <device-group-name>/<serial>/<rule-base> generic,
    # thay bằng lệnh đúng <pre-rulebase> + <post-rulebase> với wildcard (target=<serial> ở tầng request quyết định firewall).
    # SỬA 2026-10-20: thêm phạm vi <shared> pre/post (trước đây rule Shared VĨNH VIỄN không có
    # hit-count -> nhánh UNUSED không bao giờ áp dụng cho rule Shared). Nhánh <shared> là
    # BEST-EFFORT: Panorama từ chối thì chỉ log cảnh báo, rule trong DG vẫn có hit-count.
    # Chi phí hit-count nay là 4 call (DG pre/post + Shared pre/post), tổng batch 8 call
    # (4 rule-states + 4 hit) khi có target — vẫn CỐ ĐỊNH, không phụ thuộc số rule.
else:
    fresh_hit_stats = {}  # bỏ qua, không lỗi, degrade im lặng 0.7
```
Lỗi API (kể cả có target, 1 trong 4 lệnh DG/Shared × pre/post) → best-effort, `log` cảnh báo, `fresh_hit_stats` chứa phần lấy được (có thể rỗng), không chặn batch. Kịch bản "Panorama từ chối node `<shared>`" đã được chốt bằng case kiểm thử trong `testlab/run_all_features.py`.

**b) Fresh Rule States (luôn thử, 4 lệnh cố định):**
```python
fresh_states = fetch_current_rule_states(panorama_ip, api_key, verify_ssl, log_func)
# -> Optional[Dict[Tuple[str,str], dict]] khoá (rule_name, vi_tri)
#    value: {"disabled":bool, "source":[...], "destination":[...], "service":[...], "action":str}
```
Chi tiết `fetch_current_rule_states()` trong `pan_api.py:IV.6.5`:
- Gọi đúng **4 lệnh `action=get` cố định** (không phụ thuộc số DG/rule), xpath WILDCARD bỏ `[@name='DG']`:
  1. `/config/shared/pre-rulebase/security/rules`
  2. `/config/shared/post-rulebase/security/rules`
  3. `/config/devices/entry[@name='localhost.localdomain']/device-group/entry/pre-rulebase/security/rules`
  4. `/config/devices/entry[@name='localhost.localdomain']/device-group/entry/post-rulebase/security/rules`
- Với (3)/(4): response trả nhiều `<device-group><entry name='DG_X'>…<pre-rulebase>…<rules><entry name='RULE_Y'>` — **phải parse giữ tên DG cha** (duyệt lồng nhau, không `findall(".//entry")` phẳng mất ngữ cảnh). Dựng `vi_tri` đúng format `Shared-PRE/<DG>-PRE/<DG>-POST/Shared-POST` để khớp candidates.
- Với mỗi rule, đọc luôn trong cùng response (không thêm call): `<disabled>`, `<source>`, `<destination>`, `<service>`, `<action>` — lưu vào dict con cho bước lọc.
- Lỗi bất kỳ trong 4 lệnh → best-effort, `log` cảnh báo, trả `None` (coi như không xác minh được), không chặn batch.

### IV.8.3 Lọc tại chỗ trong loop (không gọi API thêm)

```python
for name, loai, vi_tri, dg, rb, action in candidates:  # giữ 6 phần tử hiện có
    state = fresh_states.get((name, vi_tri)) if fresh_states is not None else None
    # 1. Không còn tồn tại đúng (name, vi_tri) khi đã xác minh được
    if fresh_states is not None and state is None:
        # loại: "Rule không còn tồn tại đúng vị trí tại thời điểm thực thi"
        continue
    # 2. Disabled→delete nhưng đã enable lại
    if action == "delete" and state is not None and state["disabled"] is False:
        # loại: "Rule đã được enable lại, không còn là Disabled Rule"
        continue
    # 3. Shadow→disable nhưng đã disabled sẵn → bỏ qua an toàn, không fail, không gọi lại API
    if action == "disable" and state is not None and state["disabled"] is True:
        # log info "đã disabled sẵn, bỏ qua gọi API thừa", không đưa vào fail
        continue
    # 4. Shadow→disable nhưng Source/Destination/Service đã bị sửa (so list string thô, không resolve)
    if action == "disable" and state is not None and \
       (state["source"] != orig_source or state["destination"] != orig_destination or state["service"] != orig_service):
        # loại: "Rule đã bị chỉnh sửa Source/Destination/Service từ lúc Check - cần Check lại"
        continue
    # 5. Shadow→disable + có target + có fresh_hit_stats + stat.hit_count is not None (D10: 0-hit luôn None)
    #    → loại: "Hit Count đã thay đổi kể từ lúc Check - bỏ qua để an toàn"
    if action == "disable" and target_serial and fresh_hit_stats and \
       (stat := fresh_hit_stats.get((name, vi_tri))) is not None and stat.hit_count is not None:
        continue
    # ngược lại → tiếp tục gọi disable_rule_candidate()/delete_rule_candidate() như cũ
```

`orig_source/destination/service` là dữ liệu gốc lúc Check của candidate (lưu sẵn khi `find_*` hoặc từ `rule_by_key`), **SỬA 2026-09-02 audit: so sánh bằng `set()` thay vì `list` có thứ tự**, tránh coi là “đã sửa” chỉ vì PAN-OS trả `<member>` theo thứ tự khác.

### IV.8.4 Báo cáo R4 (tách biệt)

```
Disable thành công: X rule.
Delete thành công: Y rule.
Bị loại khi xác minh lại (config đã đổi từ lúc Check): Z rule.
Bỏ qua vì đã ở trạng thái mong muốn sẵn: W rule.
Lỗi API: V rule.
```
`Z` là các case 1/2/4/5 trên; `W` là case 3 (đã disabled sẵn); `V` là lỗi khi gọi `disable/delete` thật; `not_found` lúc Import ban đầu vẫn riêng. Không đổi format Excel 15 cột hay xpath Disable/Delete hiện có.

### IV.8.5 Các sửa nhỏ kèm audit 2026-09-02
- `fetch_current_rule_states()` xoá nhánh chết `if not result or all(...): pass` (dead code) — không có fallback thực chất, dễ gây hiểu lầm.
- `_on_import` bỏ chặn cứng “trùng tên ở bất kỳ DG nào cũng chặn” (kiểm tra `len([k for k in rule_by_key if k[0]==name])>1`): nay chỉ log cảnh báo nhưng vẫn cho phép xử lý chính xác theo `vi_tri` vì D9 đã sửa khoá `(name, vi_tri)`. Tránh “quá tay” làm giảm tự động hoá.
- Tài liệu ghi rõ quy tắc “trùng tên chặn cả 2 phía” trước đây để tránh bối rối admin.

---

# PHẦN V — NGUYÊN TẮC BẢO TRÌ CHUNG

> **Đọc V.4.1 trước khi commit bất cứ thay đổi nào** — đó là 7 bước bắt buộc của mỗi lần bảo trì.

**Không đổi** so với bản gốc: quy tắc "chỉ sửa file cấu phần cần action" (bảng V.1), checklist
bàn giao sau mỗi lần fix (V.2), checklist nhanh khi tiếp nhận bảo trì (V.3) — áp dụng nguyên văn,
chỉ thêm 1 dòng vào checklist V.3: **"Sửa gì liên quan tới nguồn dữ liệu Panorama (xpath, chuỗi
Device Group, target)? → đọc lại PHẦN 0 trước khi sửa, đảm bảo không phá vỡ nguyên tắc lắp ráp
0.3 hoặc thừa kế object 0.2."**

## V.4 — Quy tắc đồng bộ tài liệu & Single-File (BẮT BUỘC - hiệu lực từ 2026-08-29, siết 2026-09-02)

> **Mỗi lần chỉnh sửa code (bất kỳ file nào trong `check_rule_pan/`, `check_ip_pan/`, `check_audit_pan/`
> hoặc `tools/`), bắt buộc phải đồng thời cập nhật `PaloPANORAMA_single.md` VÀ sinh trực tiếp ra `PaloPANORAMA_single.py` trong cùng commit:**

1. **Cập nhật PHẦN XIV** — thêm 1 dòng changelog mới ở đầu danh sách (giữ nguyên các dòng cũ), ghi rõ:
   ` [YYYY-MM-DD] Tên thay đổi — file đã sửa — lý do/nghiệp vụ — người thực hiện (nếu có)`.
2. **Cập nhật đúng Phần nghiệp vụ tương ứng** (0 / II / III / IV) nếu luật/thứ tự/API thay đổi — không chỉ ghi ở XIV.
3. **Sinh trực tiếp Single-File (bắt buộc từ 2026-09-02)** — ngay sau sửa, chạy:
   `python tools/build_panorama_single.py && python -m py_compile PaloPANORAMA_single.py`
   để đảm bảo `PaloPANORAMA_single.py` luôn là bản mới nhất của 3 package `*_pan` (zip+base64, đã kiểm chứng không lệch). **Không được để source rời mới hơn single** — CI/review sẽ so sánh timestamp/hash; lệch là fail. Từ nay, mọi PR/commit có đụng `check_*_pan/*.py` mà thiếu `PaloPANORAMA_single.py` trong cùng diff sẽ bị từ chối tự động.
4. **Không tách commit** "code riêng, doc riêng, single riêng" — 1 thay đổi = 1 commit chứa cả code + md + single. Reviewer từ chối PR nếu thiếu bước 1–3.
5. **Automation (bắt buộc):** pre-commit hook `tools/check_md_sync.py` + `tools/check_single_sync.py` sẽ kiểm tra:
   - `git diff --name-only` có `*.py` nhưng không có `PaloPANORAMA_single.md` → fail
   - `git diff --name-only` có `check_*_pan/*.py` nhưng `PaloPANORAMA_single.py` không đổi hoặc `py_compile` fail → fail
   - Chạy `python tools/build_panorama_single.py --check` để verify hash single khớp source.

*Vi phạm quy tắc này được coi là thiếu bàn giao — phải bổ sung ngay trước khi merge/release.*

### V.4.1 — 7 BƯỚC TIÊN QUYẾT CỦA MỖI LẦN BẢO TRÌ (siết từ 2026-10-20)

> **Một lần bảo trì chỉ được coi là HOÀN THÀNH khi đủ 7 bước dưới đây, trong CÙNG 1 commit.**
> Lý do siết: code mới + tài liệu cũ là tình huống **tệ hơn cả không có tài liệu**, vì người sau
> tin vào tài liệu sai.

| # | Bước | Cụ thể là gì |
|---|---|---|
| 1 | **Sửa đúng file cấu phần** | Theo bảng V.1 — không đụng package khác cho 1 yêu cầu đơn lẻ. Không bao giờ sửa tay `PaloPANORAMA_single.py`. Đụng nguồn dữ liệu Panorama (xpath, chuỗi DG, `target`) → đọc lại PHẦN 0 trước. |
| 2 | **Cập nhật mục TÌNH TRẠNG HIỆN TẠI** (đầu tài liệu) | Sửa lại commit HEAD, SHA256 bản gộp, số test, số ca lab, và **bảng "đã kiểm chứng / CHƯA"** nếu hạng mục nào vừa đổi trạng thái (ví dụ vừa xác nhận được schema `<shared>` trên thiết bị thật). |
| 3 | **Thêm 1 entry vào PHẦN XIV** | Theo đúng 5 phần: **lỗi/yêu cầu là gì → nguyên nhân gốc → đã sửa thế nào → cố tình KHÔNG đổi những gì → bằng chứng đo thật** (số test PASS, số ca lab, SHA build). Entry mới đặt **trên cùng**, không xoá/sửa entry cũ. |
| 4 | **Sửa luôn mục luật tương ứng** | Luật hạ tầng đổi → sửa **PHẦN 0**; luật nghiệp vụ đổi → sửa **II/III/IV**. XIV là nhật ký, không phải luật hiện hành. |
| 5 | **Mở rộng `testlab/`** | Mỗi luật mới / lỗi vừa sửa phải có **ít nhất 1 ca trong `testlab/run_all_features.py`** chốt lại nó (thêm rule/fixture nếu cần, theo quy ước VI.3), để lần sau không ai làm hồi quy. Thêm ca → cập nhật số PASS ở mục TÌNH TRẠNG và `testlab/README.md`. |
| 6 | **Chạy thật, dán số thật** | `python -m unittest discover -s tests -q` **và** `python testlab/run_all_features.py --auto` phải xanh; dán **đúng con số đo được**. Không viết "đã test OK" suông, không nới lỏng assert, không skip test để xanh. |
| 7 | **Sinh lại bản gộp** | `python tools/build_panorama_single.py && python tools/build_panorama_single.py --check`, ghi SHA256 mới vào mục TÌNH TRẠNG. Code rời mới hơn bản gộp = lỗi bàn giao. |

**Bắt buộc nói rõ phần CHƯA làm.** Mỗi entry XIV phải có đoạn "CHƯA làm / hạn chế còn lại" — kể
cả khi chỉ là nhắc lại "chưa chạy GUI thật / chưa chạy với Panorama thật". Kết luận "hoàn tất"
mà không có số đo kèm theo là **không được chấp nhận**.

---

# PHẦN VI — MÔI TRƯỜNG KIỂM THỬ & NGHIỆM THU (`testlab/`)

Chi tiết vận hành (kể cả bảng ánh xạ từng rule trong fixture → hạng mục nó chốt) nằm ở
`testlab/README.md`. Mục này ghi **vai trò của nó trong quy trình bảo trì** và **giới hạn**,
để không ai nhầm "lab PASS" = "chạy được trên Panorama thật".

## VI.1. Hai tầng kiểm chứng, không thay thế nhau

| Tầng | Lệnh | Phủ cái gì | Không phủ cái gì |
|---|---|---|---|
| **Unit test** | `python -m unittest discover -s tests -q` | Luật nghiệp vụ thuần + 8 điểm hạ tầng PHẦN 0 ở mức hàm | Lớp HTTP: op-command thật, parse phản hồi thật, hành vi khi Panorama **từ chối** request |
| **Nghiệm thu lab** | `python testlab/run_all_features.py --auto` | Đúng các hàm mà GUI gọi, qua **HTTPS thật** tới Panorama giả lập: cả 3 tab + cả 8 điểm 0.1→0.8 | Việc **vẽ widget** (cần `python3-tk`) và **hành vi của thiết bị thật** |

Lab được nối vào bộ test chung qua `tests/test_testlab_acceptance.py` → `discover -s tests` chạy
luôn 68 ca nghiệm thu (tự `skipTest` nếu máy thiếu `cryptography`).

## VI.2. Ba điều lab cố tình làm khó tool (đừng "sửa" cho dễ)

1. **Op-command dataplane bị TỪ CHỐI khi thiếu `target=`** (`security-policy-match`,
   `rule-hit-count`) — đúng như Panorama thật. Quên truyền `target` là **lộ ra ngay** thay vì âm
   thầm trả kết quả sai. Đây là cách chốt 0.5 và 0.7.
2. **Mọi lệnh ghi chỉ ghi vào `testlab/.journal.log`**, không bao giờ sửa file cấu hình, và
   `commit` **bị từ chối** → journal là **bằng chứng kiểm tra xpath** (phải trỏ đúng
   `device-group/entry[@name=...]` + `pre|post-rulebase`), và luật D6 được chốt bằng máy.
3. **Response op-command được lồng đúng cây** (`device-group|shared` + `pre|post-rulebase`) chứ
   không trả danh sách phẳng → buộc tool phải **tự suy `Vi tri Rule`** từ chính response (D9:
   2 Device Group được phép trùng tên rule). Chính điểm này đã **lộ ra 1 lỗ hổng thật** — xem
   entry XIV ngày 2026-10-20 về hit-count bỏ sót rule Shared.

## VI.3. Quy ước fixture (phải giữ khi thêm case mới)

- Fixture là **hệ Panorama thật sự**, không phải 1 rulebase phẳng: `DG-ALL → DG-DC → DG-HN`,
  Template + Template Stack, 2 thiết bị, 13 rule rải **đủ 4 vị trí** (Shared-PRE / DG-PRE /
  DG-POST / Shared-POST), nhánh `<readonly>`, object bị DG con đè.
- Rule có tên **kết thúc bằng `-NOHIT`** → Panorama giả lập trả **0 hit**. Marker **tường minh**
  như vậy là có lý do: bản đầu đoán theo từ khoá (`SHADOW`, `OLD`…) và đã **đoán nhầm** 1 rule
  trong fixture → làm sai 1 ca kiểm thử.
- **NAT của Device Group phải nằm trong `pre-rulebase/nat/rules` hoặc `post-rulebase/nat/rules`**
  (giống security), **không** đặt thẳng dưới `<entry>` — đặt sai thì `assemble_nat_rules()` đọc ra
  0 rule. Lỗi này đã từng xảy ra trong chính fixture và bị lab bắt.
- Mỗi rule gắn với **một** hạng mục cần chốt. Thêm luật mới thì **thêm rule mới**, đừng đổi ý
  nghĩa rule đang có (làm hỏng ca khác một cách âm thầm).

## VI.4. Khi lab FAIL thì sửa ở đâu

Theo đúng thứ tự: (1) **giả định/kỳ vọng** mình viết sai → đọc lại PHẦN 0 và luật ở II/III/IV;
(2) **fixture** sai so với cấu trúc Panorama thật; (3) **mock** trả phản hồi không giống thiết bị
thật; (4) **cuối cùng** mới tới code sản phẩm. **Tuyệt đối không nới lỏng assert để lab xanh.**
Thực tế đợt 2026-10-20: 3 ca FAIL → 2 ca là **fixture sai** (NAT đặt sai tầng) và 1 ca là **lỗ
hổng thật của sản phẩm** (hit-count bỏ sót phạm vi Shared) — không ca nào là "assert quá khắt khe".

---

# PHẦN XIV — NHẬT KÝ THAY ĐỔI GẦN NHẤT

- **[2026-10-25b] Khoá lại chính BỘ SINH bản gộp — `tools/build_panorama_single.py` là mắt xích duy nhất chưa có test, mà nó lại là thứ quyết định file `.exe` chạy đúng hay không** (`tests/test_build_panorama_single.py` — 7 ca mới, không đụng một dòng code sản phẩm):
  - **Vấn đề — nguy cơ, không phải lỗi đã xảy ra.** Quy tắc V.3 bước 1 cấm sửa tay `PaloPANORAMA_single.py`: bản gộp **bắt buộc** do `tools/build_panorama_single.py` sinh ra. Nghĩa là mọi lỗi của chính bộ sinh đều đi thẳng vào sản phẩm phát hành mà **không có lưới nào chặn** — trong khi 231 test còn lại chỉ kiểm chứng *source rời*, không kiểm chứng *cái sinh ra bản gộp*. Đợt 2026-10-25a đã đụng đúng chỗ này: thêm `_replace(..., done_if=...)` + `_migrate_main()` để build tự sinh `on_close()` gọi `shutdown()` cho cả 3 tab. Hai cách hỏng rất thật của kiểu code "vá text theo mốc neo": (a) mốc neo biến mất vì ai đó sửa source → `_replace` **âm thầm không vá gì**, bản gộp thiếu `shutdown()` nhưng build vẫn báo thành công; (b) vá **hai lần** → code nhân đôi. Cả hai chỉ lộ ra khi người dùng đóng cửa sổ `.exe` và nhận `Tcl_AsyncDelete`, tức sau khi đã phát hành.
  - **Đã làm thế nào.** 7 ca, chia 2 nhóm. **Nhóm `_replace` (3 ca):** mất mốc neo → **phải `raise`**, không được đi tiếp im lặng; `new` đã có sẵn trong text → bỏ qua, **không vá lần 2**; `done_if` nhận **nhiều mốc** (str hoặc tuple) → nhận đúng cả khi chỉ một trong các mốc có mặt. **Nhóm build (4 ca):** build 2 lần liên tiếp cho ra **byte y hệt** (idempotent — chốt lại chính xác lời hứa ở mục TÌNH TRẠNG); `on_close()` trong bản gộp gọi `shutdown()` cho **cả 3 tab** (không phải 2, đúng lỗi mà `_migrate_main()` sinh ra để sửa); dựng lại dạng `on_close` **cũ 2 tab** rồi build → bộ sinh phải tự nâng lên 3 tab; và `main()` **bị sửa tay** rồi build → vẫn ra bản gộp chạy được, không `AssertionError`. Mỗi ca chạy trên **bản sao trong thư mục tạm**, không bao giờ ghi lên `PaloPANORAMA_single.py` thật.
  - **Cố tình KHÔNG đổi.** Không sửa một dòng nào trong `tools/build_panorama_single.py` lẫn 3 package — đợt này **chỉ thêm test**. Bằng chứng: SHA256 bản gộp **không đổi** so với entry 2026-10-25a (`bfef091f…`), và `--check` trả exit 0. Luật nghiệp vụ, 8 điểm đặc thù Panorama 0.1→0.8, bố cục GUI, chốt D6 (không bao giờ `commit`): nguyên vẹn.
  - **Bằng chứng đo thật.** `python3.12 -m unittest discover -s tests -q` → **231 test, OK (skipped=4)** (224 → 231, đúng 7 ca mới); `xvfb-run -a python3.12 -m unittest discover -s tests -q` → **243 test, OK, 0 skip**; `python testlab/run_all_features.py --auto` → **68/68 PASS**; `tools/build_panorama_single.py --check` → exit **0**; SHA256 `bfef091f007f50786e3b7d8226c34433c466b05d356b79479cec3febe170f435` **trước và sau** khi chạy cả bộ test (ca idempotent có ghi file nên đã đo lại sau khi chạy). Kiểm chứng ngược từng lớp, **chạy thật, dán đúng cái đo được**: (a) đổi `_replace` cho nó `return text` thay vì `raise` khi thiếu mốc neo → **2 ca đỏ** (`test_raises_when_anchor_missing` + `test_done_if_accepts_several_markers`), `FAILED (failures=2)`; (b) bỏ `_migrate_main()` khỏi `build()` → **1 ca đỏ**, `FAILED (failures=1)`, và ca đỏ là **`test_regenerates_on_close_from_old_form`** — **không phải** `test_on_close_shuts_down_all_three_tabs`. Lý do đáng ghi lại: `PaloPANORAMA_single.py` hiện tại **đã** mang dạng `on_close` 3 tab (đã migrate ở đợt trước), nên ca đọc trực tiếp bản gộp vẫn xanh dù bỏ bước migrate; chỉ ca **dựng lại dạng cũ 2 tab rồi build** mới thật sự kéo `_migrate_main()` ra chạy. Nói cách khác ca `old_form` là cái duy nhất canh bước migrate; ca 3 tab canh **trạng thái hiện tại của sản phẩm**. Giữ cả hai, không gộp. Hoàn nguyên cả (a) và (b) → `git diff` sạch, `--check` exit 0, SHA256 về đúng `bfef091f…`.
  - **CHƯA làm / hạn chế còn lại.** (1) **Không thêm ca vào `testlab/`** (lệch bước 5 của V.4.1, có chủ đích): `testlab/` là tầng nghiệm thu nghiệp vụ qua Panorama giả lập, không dựng được quy trình build — thay vào đó chốt bằng 7 ca ở `tests/`, chạy cùng một lệnh `unittest discover`, nên không có đường hồi quy nào bị bỏ hở. (2) Test chứng minh bản gộp **sinh ra đúng** và **import được**, **không** chứng minh `.exe` đóng bởi PyInstaller chạy đúng trên Windows — vẫn cần 1 lần đóng gói và mở thật. (3) Ba hạn chế lớn của entry trước **không đổi**: chưa nhìn bố cục GUI trên Windows thật, **chưa chạy với Panorama THẬT**, schema `<shared>` của `rule-hit-count` chưa xác nhận trên thiết bị (vẫn suy giảm mềm có chủ đích), rule cục bộ trên firewall chưa có ô nạp trên GUI.

- **[2026-10-25a] CẢ 3 TAB: worker thread chạm thẳng vào Tkinter — Export NAT hỏng, Load Config hỏng, chế độ "Chọn file" mất trắng lượt chạy** (`check_rule_pan/gui.py`, `check_ip_pan/gui.py`, `check_audit_pan/gui.py`, `check_ip_pan/core.py`, `check_audit_pan/core.py`, `tools/build_panorama_single.py`, 4 file test mới):
  - **Lỗi — Tkinter không thread-safe, nhưng 11 chỗ trong 3 tab gọi thẳng từ worker thread.** Phát hiện bằng cách lái thật giao diện trên Panorama giả lập (thứ mà bảng "đã kiểm chứng" trước đây ghi là **CHƯA**). Ba triệu chứng thật, tái hiện 100%:
    1. `check_ip_pan` — bấm Check/Export có bật mục 4 → `"Da xay ra loi khong xac dinh"`. 4 chỗ gọi `self.lbl_progress.config()` trong `_run_all_worker()`/`_run_nat_pipeline()`.
    2. `check_rule_pan` — **Load Config luôn thất bại**: `self.cmb_dg['values'] = dg_list`, `self.cmb_target['values'] = [...]` (phép gán `__setitem__` → `configure()`) và `self.dg_var.set(...)` đều chạy trong worker.
    3. `check_rule_pan` — chế độ **"Chọn file" không bao giờ sinh file kết quả**: `self.req_file_var.get()` đọc `tk.StringVar` từ worker, nổ **đúng lúc chuẩn bị xuất Excel**, tức sau khi đã tốn toàn bộ thời gian quét rulebase.
  - **Vì sao bộ test cũ không bắt được.** `testlab/run_all_features.py` gọi **thẳng các hàm pipeline**, không đi qua tầng GUI — nên **68/68 vẫn PASS** trong khi 3 luồng trên hỏng hoàn toàn với người dùng thật.
  - **Đã sửa thế nào.** `check_rule_pan`: thêm `_ui_queue` + `_ui(func)` (cùng cơ chế `_log_queue` đã có), `cancel_event`/`_closing`/`shutdown()` đúng chữ ký 2 tab kia, đọc `req_file_var` một lần trên main thread rồi truyền qua closure, dừng sớm khi `cancel_event` bật. `check_ip_pan`: thêm message `status` + `_set_status()` vào `_poll_queue`. Cả `check_ip_pan` lẫn `check_audit_pan`: `_poll_after_id` + `shutdown()` huỷ vòng `after` đang treo. Cả 2 `core.py`: đóng log handler trước khi bỏ (rò file descriptor). `tools/build_panorama_single.py`: thêm `_replace(..., done_if=...)` + `_migrate_main()` để **chính build** sinh ra `on_close()` gọi `shutdown()` cho cả 3 tab — **không sửa tay** `PaloPANORAMA_single.py`, đúng quy tắc V.3 bước 1.
  - **Lưới chặn tái phạm (`tests/test_gui_thread_safety.py`).** Bộ quét AST đi **đệ quy** từ hàm `target=` của `threading.Thread` sang mọi hàm nó gọi, giữ **danh sách** hàm thay vì dict (nhiều hàm lồng nhau trùng tên `_worker` — dùng dict chỉ giữ cái cuối, bỏ lọt hết phần còn lại), và bắt 4 dạng: gọi `messagebox/filedialog`, gọi `self.after()`, gọi method đổi/đọc widget (`config/insert/get/set/cget...`), và **phép gán `self.<widget>[...] = ...`**. Chỉ tính thuộc tính đặt tên theo quy ước widget của 3 tab để không báo nhầm dict thường như `self.rule_by_key[k] = v`.
  - **Thêm E2E GUI cho cả 3 tab** (`test_gui_e2e_check_rule.py` 4 ca, `test_gui_e2e_check_ip.py` 3 ca, `test_gui_e2e_check_audit.py` 3 ca) lái thật giao diện trên Panorama giả lập. Mọi test tự dọn file sinh ra.
  - **Cố tình KHÔNG đổi.** Không đụng một dòng luật nghiệp vụ nào của cả 3 tool, không đụng 8 điểm đặc thù Panorama (0.1 → 0.8), không đổi bố cục giao diện. Hộp thoại vẫn hiện đúng như cũ — chỉ khác là hiện từ main thread.
  - **Bằng chứng đo thật.** `python -m unittest discover -s tests -q` → **224 test, OK (skipped=5)**; máy có Tk → **236 test, OK, 0 skip**. `testlab/run_all_features.py --auto` → **68/68 PASS**. Bản gộp SHA256 `bfef091f007f50786e3b7d8226c34433c466b05d356b79479cec3febe170f435`, 253161 ký tự, build idempotent. Kiểm chứng ngược cho từng lớp lỗi: trả lại `self.cmb_dg['values'] = ...` → test đỏ đúng dòng đó; vá xong → xanh.
  - **CHƯA làm / hạn chế còn lại.** (1) Chưa ai nhìn bố cục GUI trên Windows thật — toàn bộ headless qua Xvfb trên Linux. (2) Chưa chạy với Panorama THẬT. (3) E2E gọi đúng handler mà nút bấm gọi, chưa mô phỏng click ở mức toạ độ pixel. (4) Không thêm ca vào `testlab/` vì lỗi nằm ở tầng GUI, lab không dựng được vòng đời cửa sổ Tk — đã chốt bằng 4 file test ở `tests/`.

> Chỉ liệt kê ngắn gọn. Chi tiết luật nghiệp vụ đã có sẵn ở Phần 0/II/III/IV — không lặp lại.
> **Quy tắc V.4**: mỗi dòng dưới đây tương ứng 1 commit đồng bộ code + md + single (từ 2026-09-02, single luôn sinh trực tiếp).

- **[2026-10-20b] Tài liệu: thêm mục TÌNH TRẠNG HIỆN TẠI + PHẦN VI (Môi trường kiểm thử) + I.2 cây thư mục thật + V.4.1 QUY TẮC TIÊN QUYẾT 7 bước — file đã sửa: `PaloPANORAMA_single.md` — lý do: tài liệu đã đủ LUẬT nhưng thiếu 3 thứ mà người tiếp nhận bảo trì cần ngay: bản hiện tại là gì, đã kiểm chứng tới đâu, và quy trình bắt buộc mỗi lần sửa.**
  - **Thiếu "ảnh chụp hiện tại"**: muốn biết bản này ở đâu, kiểm chứng tới đâu thì phải đọc ngược toàn bộ changelog XIV rồi tự ghép. Thêm mục **TÌNH TRẠNG HIỆN TẠI** ngay đầu tài liệu: commit HEAD, branch, SHA256 bản gộp, số test, số ca lab, kèm **bảng "đã kiểm chứng / CHƯA"** nói thẳng 5 thứ chưa làm được (GUI thật, Panorama thật, schema `<shared>` của hit-count, rule cục bộ trên firewall, và việc `policy-match`/`rule-hit-count` trong lab chỉ là mô phỏng).
  - **`testlab/` chỉ được mô tả trong 1 entry changelog** → dễ hiểu nhầm "lab PASS = chạy được trên Panorama thật". Thêm **PHẦN VI**: 2 tầng kiểm chứng phủ/không phủ cái gì; **3 điều lab cố tình làm khó tool** (từ chối op-command thiếu `target`, chỉ ghi journal + từ chối `commit`, trả response **lồng đúng cây** để buộc tool tự suy `Vi tri Rule`); quy ước fixture phải giữ (hệ Panorama thật 3 DG, marker `-NOHIT`, **NAT phải nằm trong pre/post-rulebase**, mỗi rule chốt 1 hạng mục); và **thứ tự truy nguyên khi lab FAIL** (giả định → fixture → mock → cuối cùng mới tới code; tuyệt đối không nới lỏng assert). Ghi lại luôn kết quả thật của đợt này: 3 ca FAIL = 2 ca fixture sai + 1 **lỗ hổng thật của sản phẩm**, không ca nào do assert khắt khe.
  - **I.2 cây thư mục**: trước đây chỉ có 1 đoạn văn trỏ sang tài liệu bản standalone và còn gọi package theo tên cũ `check_rule/`, `check_ip/`. Nay có cây thư mục thật với hậu tố `_pan`, kèm `tests/` và `testlab/`, mỗi file 1 dòng vai trò; đổi `I.2–I.8` thành `I.3–I.8`. Sửa luôn I.1 còn ghi tên bản gộp legacy `PaloRuleSearchSuite_single.py`.
  - **Siết quy tắc bảo trì (V.4.1)**: từ nay 1 lần bảo trì chỉ HOÀN THÀNH khi đủ **7 bước trong CÙNG 1 commit** — (1) sửa đúng file cấu phần (đụng nguồn dữ liệu Panorama thì đọc lại PHẦN 0 trước); (2) cập nhật mục TÌNH TRẠNG HIỆN TẠI; (3) thêm entry XIV theo đúng 5 phần *lỗi → nguyên nhân gốc → cách sửa → cố tình KHÔNG đổi gì → bằng chứng đo thật*; (4) sửa luôn PHẦN 0 (nếu luật hạ tầng đổi) hoặc II/III/IV (nếu luật nghiệp vụ đổi); (5) **mở rộng `testlab/` để mỗi lỗi vừa sửa có ít nhất 1 ca chốt lại**; (6) chạy thật và **dán số thật**; (7) sinh lại bản gộp + `--check` + ghi SHA mới. Kèm yêu cầu **bắt buộc nói rõ phần CHƯA làm** trong mỗi entry.
  - Kiểm chứng: chỉ sửa tài liệu, **không đụng một dòng code nào** → `discover -s tests` vẫn **221 test OK (skipped=1)**, `testlab/run_all_features.py --auto` vẫn **68/68 PASS**, `tools/build_panorama_single.py --check` vẫn báo đồng bộ, `PaloPANORAMA_single.py` giữ nguyên SHA256 `290f0125b1d14f05238ad29ea1d678862adc5b540fb3eaaf81ef3252e4cb4adb`.
  - **CHƯA làm / hạn chế còn lại:** không đổi so với entry dưới — vẫn chưa chạy GUI thật, chưa chạy với Panorama thật, schema `<shared>` của `rule-hit-count` chưa xác nhận trên thiết bị (đã suy giảm mềm), rule cục bộ trên firewall chưa có ô nạp trên GUI.

- **[2026-10-20] MÔI TRƯỜNG CHẠY THỬ `testlab/` (Panorama giả lập) + vá lỗ hổng hit-count KHÔNG BAO GIỜ áp dụng cho rule Shared — file đã sửa/thêm: `testlab/{mock_panorama_api.py,make_samples.py,run_all_features.py,README.md}`, `testlab/fixtures/{running_config.xml,candidate_config.xml}`, `tests/test_testlab_acceptance.py`, `check_audit_pan/pan_api.py`, `tests/test_verify_batch.py`, `.gitignore` — lý do: trước đợt này toàn bộ kiểm chứng là unit test với XML giả lập trong RAM, chưa có đường nào chạm tới lớp HTTP/HTTPS thật và chưa có cách để người dùng tự nghiệm thu trước khi mang ra Panorama production.**

  **A. `testlab/mock_panorama_api.py` — Panorama giả lập nói đúng XML API.** HTTPS + cert tự ký sinh tại chỗ vào `testlab/.certs/` (gitignore, **không commit private key**). Hỗ trợ: `type=config&action=show|get` với bộ giải `xpath` tối giản, `type=op` cho `<show><devicegroups/>`, `<show><devices><all/></devices></show>`, `security-policy-match` (mô phỏng theo đúng thứ tự lắp ráp 0.3, zone suy từ interface theo longest-prefix, resolve group đệ quy), `rule-hit-count`, `registered-ip`. **Hai điểm cố tình làm khó tool, đúng như Panorama thật:** (1) mọi op-command dataplane (`policy-match`, `rule-hit-count`) **bị từ chối nếu thiếu `target=`** → nếu code quên truyền target là lộ ra ngay thay vì âm thầm trả kết quả sai (chốt 0.5/0.7); (2) mọi lệnh ghi **chỉ ghi vào `testlab/.journal.log`**, không bao giờ sửa file cấu hình, và `commit` **bị từ chối** (chốt D6 — trên Panorama còn nguy hiểm hơn vì có thêm tầng *Commit and Push*).

  **B. `testlab/fixtures/running_config.xml` — hệ Panorama 3 DG lồng nhau** (`DG-ALL → DG-DC → DG-HN`), 1 Template + 1 Template Stack, 2 thiết bị, **13 security rule rải đủ 4 vị trí** (Shared-PRE / DG-PRE / DG-POST / Shared-POST) + **2 NAT rule**, nhánh `<readonly>` chứa bản sao `parent-dg`, object bị DG con đè, group lồng group, DAG, FQDN. Mỗi rule gắn với **một** hạng mục cần chốt (bảng đầy đủ trong `testlab/README.md`), trong đó `A90-DGALL-POST-NOHIT` chứng minh **DG-POST đảo chiều**, `D03B-ZONE-ANY-OK` chốt lại **fix `_zones_cover`**, `H03-ALLOW-BADNET-ANYWAY` chứng minh rule deny ở Shared-PRE chặn trước rule allow của DG. `candidate_config.xml` = running + 1 object + 1 rule chưa commit.

  **C. `testlab/run_all_features.py --auto` — nghiệm thu 1 lệnh, `68/68 PASS`.** Gọi **đúng các hàm mà GUI gọi** (cùng pipeline, cùng exporter), không viết lại logic; in bảng PASS/FAIL, exit code 0/1 dùng được cho CI. Phủ cả 3 tab và **cả 8 điểm đặc thù Panorama 0.1→0.8**, trong đó có các case chỉ bản Panorama mới có: chuỗi thừa kế object 3 tầng + DG gần đè DG xa, đổi DG thì phạm vi đổi theo (`DG-ALL` 4 rule / `DG-HN` 13 rule), thứ tự lắp ráp 6 bước, nhãn `Vi tri Rule` đúng cho **cả security lẫn NAT**, candidate lọc ra phần THẬT SỰ mới, Live Match **cả hai chiều** (có target → khớp rule thật; thiếu target → **0 API call** rồi rơi xuống LOCAL), Zone từ Template của đúng Target và **tự vô hiệu im lặng** khi thiếu Target, hit-count khoá `(name, vi_tri)` đủ 4 phạm vi, xpath ghi trỏ đúng `post-rulebase` của đúng DG, và **không một lệnh `commit` nào**. Nối vào bộ test chung qua `tests/test_testlab_acceptance.py` → `python -m unittest discover -s tests -q` nay là **221 test PASS** (220 unit + 1 case gói trọn 68 kiểm tra nghiệm thu, tự SKIP nếu máy thiếu `cryptography`).

  **D. Lỗ hổng tìm ra NHỜ lab (không phải lỗi của lab).** Khi mock trả response `rule-hit-count` **lồng đúng cây** như thiết bị thật (`device-group|shared` + `pre|post-rulebase`) thay vì một danh sách phẳng, lộ ra: `fetch_rule_hit_count()` chỉ hỏi phạm vi **Device Group**, nên rule `Shared-PRE`/`Shared-POST` **vĩnh viễn không bao giờ** có hit-count → nhánh **UNUSED không bao giờ áp dụng cho rule Shared** (đúng chỗ dễ tồn đọng rule chết nhất). Đã thêm 2 lệnh phạm vi `<shared>` pre/post: chi phí hit-count 2→4 call, tổng batch 6→8 call, **vẫn cố định**, không phụ thuộc số rule. Nhánh `<shared>` để **best-effort có chủ đích** (bọc `try/except`, từ chối thì log cảnh báo và đi tiếp) vì chưa xác nhận được schema này trên Panorama thật — và chính kịch bản "Panorama từ chối `<shared>`" được chốt bằng 1 case trong lab: tool **không raise, không trả rỗng**, rule trong DG vẫn đủ hit-count. Cập nhật `tests/test_verify_batch.py::test_08_fixed_cost` 6→8 (điểm cần giữ là **độc lập với số rule N**, không phải con số).

  **E. Sửa 2 chỗ sai trong chính fixture (phát hiện khi lab FAIL, không nới lỏng assert để che):** (1) NAT của Device Group bị đặt thẳng dưới `<entry>` thay vì trong `pre-rulebase/nat/rules` — trên Panorama NAT cũng nằm trong pre/post-rulebase như security, nên `assemble_nat_rules()` (code **đúng**) đọc ra 0 rule; đã chuyển `NAT01` vào pre, `NAT02` vào post để chốt luôn cả 2 nhánh. (2) `tests/test_verification.py` (bản standalone) và `tests/test_verify_batch.py::test_11` import GUI ở tầng module nên **làm đổ cả bộ test** trên máy không có `python3-tk`; nay tự `skipTest` với lý do rõ ràng.

  **F. CHƯA làm / hạn chế còn lại:** (1) vẫn **chưa chạy được GUI thật** (container không có `python3-tk`) — lab chạy thẳng vào các hàm GUI gọi, nhưng phần vẽ widget chỉ có `py_compile`; `testlab/README.md` mục 2 ghi sẵn đúng thông số để người dùng tự mở GUI trỏ vào mock (`127.0.0.1:8443`, DG `DG-HN`, Target `001122334455`). (2) `security-policy-match` và `rule-hit-count` của lab là **mô phỏng** theo file config, rất sát nhưng không phải dataplane/Policy Optimizer thật. (3) Schema `<shared>` của `rule-hit-count` cần xác nhận trên Panorama thật (đã suy giảm mềm nên không rủi ro). (4) Lab cố tình **không** mô phỏng tầng *Commit and Push*.

- **[2026-10-20] ĐỒNG BỘ TOÀN DIỆN VỚI BẢN FIREWALL STANDALONE + VÁ 6 LỖI HẠ TẦNG PANORAMA — file đã sửa: toàn bộ `check_rule_pan/*`, `check_ip_pan/{core,excel_export,gui,pan_api,resolver_engine}.py`, `check_audit_pan/{detectors,resolver,pan_api,gui}.py`, `tools/build_panorama_single.py` (viết lại), xoá `tools/build_single.py` + `tools/rebuild_direct.py`, thêm 6 file test — lý do: repo fork từ bản standalone ở mốc 2026-09-02, từ đó bản gốc có 8 đợt sửa lỗi/tối ưu CHƯA được mang sang; đồng thời audit lại phát hiện 6 lỗi hạ tầng Panorama khiến 2 tính năng (Zone, danh sách Device Group) không bao giờ chạy đúng.**

  **A. Đồng bộ luật nghiệp vụ (nguyên tắc: logic nghiệp vụ GIỮ NGUYÊN 100%, chỉ khác lớp hạ tầng — PHẦN 0).** Cách làm: với mỗi file, xác định nó có chứa code Panorama riêng hay không. File THUẦN nghiệp vụ (`check_rule_pan/{resolver,index,request}.py`, `check_ip_pan/resolver_engine.py`, `check_audit_pan/resolver.py`) → lấy NGUYÊN VĂN bản standalone mới nhất. File có code Panorama (`matcher.py`, `exporter.py`, `core.py`, `detectors.py`, 3 `gui.py`, `excel_export.py`) → lấy bản standalone mới rồi ÁP LẠI đúng phần delta Panorama. Các đợt sửa được mang sang: fix "input dạng IP RANGE đã tồn tại nhưng báo cần ADD" (4 root cause: parse 15 định dạng range, union coverage nhiều member, member bounds trùng khít, TOP2/TOP3 `wide_fully_covered`); `wide_full_match`; full-set exact match; cost-priority TOP2/TOP3; Global Find + `find_existing_range_representation`; tối ưu `_scan_all_tiers` 1 lượt quét; Live Match v3 (early-stop, semaphore dùng chung, combo cache, `max_combos` cấu hình được, caveat skip minh bạch); CHECK IP gộp 1 nút "Check / Export" + `build_run_plan()` thuần tuý + gộp 1 file 2 sheet; CHECK AUDIT tối ưu bisect + ngưỡng Unused cấu hình được.

  **B. 6 lỗi HẠ TẦNG PANORAMA đã vá** (đều là lỗi chỉ tồn tại ở bản này):
  1. `resolve_template_for_serial()` (CẢ `check_rule_pan/core.py` LẪN `check_audit_pan/pan_api.py`) tra cứu **NGƯỢC CHIỀU**: tìm `/config/devices/entry[@name=<serial>]` rồi đọc thẻ `<template>` bên trong. Trên Panorama nhánh `/config/devices/entry` là chính PANORAMA (`localhost.localdomain`), KHÔNG có entry theo serial firewall → hàm **luôn trả None**, nghĩa là tính năng Zone (0.6) **chưa bao giờ chạy**. Quan hệ thật lưu ngược lại: `template/entry[@name=T]/devices/entry[@name=<serial>]` và `template-stack/entry[@name=S]/devices/entry[@name=<serial>]`. Thay bằng `resolve_templates_for_serial()` quét đúng chiều, ưu tiên Template Stack và trả danh sách template thành viên theo thứ tự ưu tiên (member đầu = ưu tiên cao nhất → nạp sau cùng để đè).
  2. `parse_interface_subnets()` / `parse_zones()` đọc sai tầng cho Template: trong Template đường dẫn thật là `template/entry/config/devices/entry/network` và `.../vsys/entry/zone` (thừa 1 tầng `<config>`, và 1 Template có thể chứa NHIỀU vsys). Nay thử lần lượt các dạng + fallback `.iter()`, gom tất cả nhánh `<zone>` và hợp member khi trùng tên zone.
  3. `get_panorama_devicegroups()` dùng selector `.//devicegroup/entry` (SỐ ÍT) nên luôn rỗng, rồi fallback `.//entry` — mà `.//entry` bắt trúng cả `<devices><entry name="<serial>">` bên trong → **SERIAL bị hiểu thành TÊN DEVICE GROUP**. Nay chỉ nhận đúng `devicegroups/entry`; lỗi/không hỗ trợ → trả `[]` để GUI đọc thẳng từ config (đường tin cậy hơn).
  4. `fetch_panorama_config_xml()` thiếu `xpath` và không có đường lùi: nay thử cách đã kiểm chứng (không xpath) trước, bị từ chối thì thử lại với `xpath=/config` (cách ghi trong tài liệu chính thức) rồi mới báo lỗi.
  5. `_extract_config()` dính bẫy ElementTree `root.find(".//msg/line") or root.find(".//msg")` — `Element.__bool__` trả False khi phần tử KHÔNG CÓ CON, mà `<line>` là thẻ lá → biểu thức `or` luôn rơi sang vế phải, **mất thông báo lỗi thật** từ Panorama. Thay bằng `_api_error_message()` kiểm tra `is None` tường minh + nối nhiều `<line>`.
  6. `_devicegroup_entries()` mới: config Panorama có DG ở **2 nơi** — `/config/devices/.../device-group/entry` (chứa object + rulebase THẬT) và `/config/readonly/...` (bản sao chỉ-đọc, thường CHỈ có `<parent-dg>`). Code cũ lấy phần tử đầu tiên gặp theo thứ tự tài liệu → nếu trúng bản readonly thì DG sẽ "rỗng không có rule nào". Nay ưu tiên tuyệt đối nhánh ngoài `<readonly>`, chỉ đọc `<parent-dg>` từ cả hai.

  **C. Bổ sung theo tinh thần "quản lý nhiều firewall":** ô Target Firewall đổi từ gõ tay sang **Combobox** nạp từ `get_panorama_devices()` (`<show><devices><all/></devices></show>`) — gõ sai 1 ký tự serial thì Live Match/Zone im lặng không chạy, rất khó phát hiện; `devicegroup_devices()` + cảnh báo khi serial **không thuộc** Device Group đang chọn; nhãn hiển thị **chuỗi thừa kế DG** ngay trên GUI (`Shared -> DG-ALL -> DG-DC -> DG-HN`) để không hiểu nhầm phạm vi; `_detect_vsys_for_target()` suy ra vsys thật của firewall đích cho Live Match (0.5); cột "Vi tri Rule" nay điền cả cho dòng TOP4/near-match (dùng `res.rule or res.nearest_rule`) thay vì để trống.

  **D. Dọn dẹp (cái sai thì bỏ):** xoá `tools/build_single.py` (bản copy nguyên từ repo firewall, trỏ sai file) và `tools/rebuild_direct.py` (chỉ thay khối base64, **không** sinh lại khối "import lộ thiên" nên thư viện mới thêm như `bisect` sẽ thiếu khi build `.exe` → `ModuleNotFoundError`); viết lại `tools/build_panorama_single.py` mô phỏng đúng bản standalone đã kiểm chứng: tự quét AST sinh lại khối import lộ thiên, build **idempotent**, và hỗ trợ `--check` (tài liệu V.4 đã nhắc lệnh này nhưng script cũ không hề có). File single nay nhúng package theo **TÊN THẬT** `check_rule_pan/...` thay vì đổi tên thành `check_rule` — khớp đúng cấu trúc repo, stack trace chỉ đúng module. Xoá `parse_nat_rules()` chết trong `check_ip_pan/pan_api.py`; 3 hàm đọc theo vsys còn lại được ghi chú CẢNH BÁO rõ "KHÔNG phải bộ chọn phạm vi của bản Panorama".

  **E. Kiểm chứng (bằng chứng, không kết luận suông):** `python -m unittest discover -s tests` → **217 PASS** (83 test cũ nguyên vẹn + 134 mới/port). Trong đó: `tests/test_panorama_infra.py` **33 test** phủ riêng PHẦN 0 (chuỗi DG 3 tầng, cắt vòng cha-con hỏng, không lấy nhầm bản readonly, object override 3 tầng, DG anh em không thấy object của nhau, thứ tự lắp ráp 6 bước + POST ngược chiều PRE, rule cục bộ nằm giữa, shadow dùng đúng thứ tự đã lắp ráp, Template Stack, zone tự vô hiệu khi thiếu target, Live Match bắt buộc target + đúng tham số `target`/`vsys`, devicegroups không lấy nhầm serial, `_api_error_message`, retry xpath, candidate theo DG); `tests/test_check_rule_pan_e2e.py` **9 test** chạy thật từ config → classify → xuất Excel → đọc lại (cột "Vi tri Rule" đúng vị trí, sheet Chú thích nói rõ 2 tầng commit); `tests/test_check_ip_pan_e2e.py` **7 test** (phạm vi theo DG-chain, cột Vi tri Rule, gộp 1 file 2 sheet); port nguyên 9 bộ test nghiệp vụ của bản standalone (range report, fullset exact, cost-priority, wide_full_match, tie-break, group order, screenshot E2E, run-plan, combined export) — 2 test Live Match được sửa để truyền `target_serial` và **thêm 1 test mới** khẳng định "thiếu target thì KHÔNG gọi API"; differential 600 kịch bản ngẫu nhiên chứng minh bản tối ưu `_covers_rule_fast` cho kết quả **0 sai lệch** so với `_covers_rule` chậm, đồng thời giữ nguyên luật `_zones_cover` đã sửa. `py_compile` toàn bộ OK. Build idempotent SHA256 `dc97d974e7977e03b11e648c95fdbfc3559ece3af42ab5746bda0984176beae4` (250346 ký tự, 22 file py), `--check` trả 0 khi đồng bộ / 1 khi lệch (đã thử cả 2 chiều). Kiểm chứng lại **trên chính file single**: 3 package import từ bộ nhớ (không giải nén ra đĩa), cách ly namespace `True`, đủ 12 hạng mục (chuỗi DG, override object, thứ tự rule, zone từ Template, fix range, gộp 2 sheet, fix zone-cover, Live Match bắt buộc target, xuất Excel có cột Vi tri Rule).

  **F. CHƯA làm / hạn chế còn lại (nói rõ, không giấu):** (1) **Chưa chạy được GUI thật** — container không có `python3-tk`; 3 `gui.py` chỉ được kiểm chứng bằng `py_compile` + import với tkinter giả lập. (2) **Chưa chạy với Panorama thật** — toàn bộ kiểm chứng dùng config XML giả lập + mock HTTP; các đường API (`target`, `<show><devices><all/></devices></show>`, retry xpath) đúng theo tài liệu nhưng CẦN xác nhận trên thiết bị thật. (3) Rule **cục bộ trên firewall** (0.3 bước 3) đã có hàm đọc + vị trí lắp ráp đúng nhưng GUI chưa có ô nạp file config firewall — mặc định `local_rules=None`. (4) `_detect_vsys_for_target()` mặc định `vsys1` khi Panorama không lưu vsys của thiết bị — cần kiểm thực tế với firewall nhiều vsys. (5) Pre-commit hook `tools/check_md_sync.py` tài liệu V.4 nhắc tới vẫn **chưa tồn tại** (đã bù `--check` cho phần single).

- **[2026-09-02] Vá audit lần 2 — sửa _zones_cover false-positive, chặn cycle DG chain, dọn dead code — file đã sửa: check_audit_pan/detectors.py:116, check_rule_pan/core.py:359, check_audit_pan/pan_api.py:364, check_ip_pan/pan_api.py:189, PaloPANORAMA_single.md — lý do: audit phát hiện _zones_cover sai khi R2=any, cycle DG chain treo vô hạn, dead code _find_unused_rules.** Chi tiết: (1) `_zones_cover` sửa `if "any" in z1 or "any" in z2: return True` → `if "any" in z1: True; if "any" in z2: False` để tránh false-positive Shadow khi R2 any còn R1 cụ thể (rủi ro xoá nhầm). (2) `resolve_devicegroup_chain` 3 nơi thêm `visited=set()` chặn cycle nhiều cấp A→B→C→A. (3) `_find_unused_rules` xoá fallback `result[(r.name,"")]` vô điều kiện gây ghi đè khi trùng tên khác DG. Không đổi logic detector khác, D6, format 15 cột.

- **[2026-09-02] Vá audit PaloPANORAMA_single.py (check_audit) — sửa 2 lỗi nghiêm trọng + 3 vấn đề nhỏ — file đã sửa: detectors.py, pan_api.py, gui.py, PaloPANORAMA_single.md — lý do: audit giải nén single phát hiện UNREACHABLE còn sót D9 + hit-count sai cú pháp.** Chi tiết audit: (1) **UNREACHABLE D9 còn sót:** `_find_unreachable_rules()` khoá `shadow` theo tên thuần `r2.name`, nay sửa khoá `(r2.name, r2.vi_tri)` đồng bộ với UNUSED, mọi tra cứu `unreachable_map` đổi sang `(name, vi_tri)` + fallback tên thuần cho test cũ. Nếu không, 2 rule cùng tên ở 2 DG khác nhau ghi đè nhau, gán sai `shadowed_by` hoặc mất Finding. (2) **Hit-count sai cú pháp:** cmd cũ chứa `<device-group-name>/<serial>/<rule-base>` generic + wildcard, PAN-OS trả lỗi cú pháp → UNUSED luôn rỗng. Sửa thành 2 lệnh đúng `<pre-rulebase>` + `<post-rulebase>` với wildcard (`target=<serial>` quyết firewall), chi phí hit-count từ 1→2 call, tổng batch từ 5→6 call (4 rule-states +2 hit). Ghi chú lab: nếu wildcard op không hỗ trợ, cần loop theo DG cụ thể. (3) **Nhỏ:** xoá dead code `if not result or all(...): pass` trong `fetch_current_rule_states`, đổi so sánh S/D/S từ `list` sang `set` tránh sai do thứ tự `<member>`, nới chặn cứng “trùng tên ở bất kỳ DG nào cũng chặn” trong `_on_import` — nay chỉ log cảnh báo nhưng vẫn xử lý chính xác theo `vi_tri` (D9 đã sửa). Không đổi D6 no-commit, format 15 cột, xpath.

- **[2026-09-02] Thêm xác minh batch trước Disable/Delete + sửa lỗ hổng fetch_rule_hit_count khoá theo tên rule thuần (vi phạm D9 khi trùng tên khác DG) — file đã sửa: pan_api.py, gui.py — lý do: giảm rủi ro thao tác trên config đã đổi giữa lúc Check và lúc thực thi, chi phí cố định 4-5 API call/batch (sau vá audit 6 call) không phụ thuộc số rule.** Chi tiết: (1) Sửa `fetch_rule_hit_count()` (cả `PanApiClient` và wrapper) trả `Dict[Tuple[str,str], RuleHitStat]` khoá `(rule_name, vi_tri)` thay vì tên thuần; rà soát `gui._delete_worker` cập nhật tra cứu. (2) Thêm `fetch_current_rule_states()` 4 lệnh `action=get` wildcard cố định (Shared-PRE/POST + DG-PRE/POST) parse giữ DG cha, dựng `vi_tri`, trả `Dict[(rule_name,vi_tri)->{disabled,source,destination,service,action}]`. (3) Sửa `_delete_worker(candidates, mgmt_ip, api_key, verify_ssl, target_serial)` thêm `target_serial`, batch xác minh `fresh_hit_stats` (nếu có target, nay 2 call) + `fresh_states`, lọc tại chỗ 5 điều kiện R3, báo cáo R4 tách `Disable OK / Delete OK / Bị loại khi xác minh lại / Bỏ qua đã mong muốn / Lỗi API`. Không đổi detector/format 15 cột/xpath (UNREACHABLE sau đó được vá ở dòng trên), D6 no-commit, dùng Candidate Config `action=get` cho xác minh (ngoại lệ 0.4). (4) Tài liệu: thêm **IV.8**, cập nhật **IV.6**, siết **V.4** sinh trực tiếp `PaloPANORAMA_single.py`.

- **[2026-08-29] CHECK AUDIT — Phân biệt Import theo loại + Quy tắc đồng bộ .md (V.4).**
  (1) `check_audit_pan`: Shadow Rules có `hit_count==0` (UNUSED 0 hits) khi Import **chỉ cho phép Disable**
  (gọi `disable_rule_candidate` → `action=set` `<disabled>yes</disabled>`, không xóa), **Disabled Rules khi Import cho phép Delete** (`delete_rule_candidate`), **Overly Permissive chỉ Export** (Import bỏ qua hoàn toàn, log cảnh báo). Popup xác nhận hiển thị cột "Hành động" (Disable màu cam / Delete màu đỏ), worker tách nhánh `disable` vs `delete`, kết quả báo cáo riêng `Disable OK / Delete OK`. `excel_io.parse_import_file` mở rộng đọc cột `Hit Count` (trả 4-tuple) để xác định hit==0 chính xác, giữ tương thích file cũ không có cột. (2) `pan_api`: thêm `PanApiClient.disable_rule_candidate()` + wrapper `disable_rule_candidate()`. (3) Tài liệu: thêm **V.4 Quy tắc đồng bộ tài liệu** — mọi chỉnh sửa code bắt buộc cập nhật đồng thời XIV + rebuild single trong cùng commit, kèm checklist và automation gợi ý. File đã sửa: `check_audit_pan/pan_api.py`, `check_audit_pan/excel_io.py`, `check_audit_pan/gui.py`, `PaloPANORAMA_single.md`; rebuild `PaloPANORAMA_single.py`.

- **[2026-08] Chuyển đổi toàn bộ Suite từ Firewall standalone sang Panorama.** Giữ nguyên 100%
  luật nghiệp vụ của cả 3 tool (thứ tự tier, điều kiện exact-scope, 3 quy tắc loại rule quá rộng,
  thuật toán shadow-check 5-điều-kiện-superset, 3 detector CHECK AUDIT, format Excel/rich-text,
  quy tắc validate GUI). Thay đổi tập trung ở lớp hạ tầng (PHẦN 0 mới): (1) Object resolution nay
  thừa kế theo chuỗi Device Group cha-con + Shared thay vì "1 vsys + shared"; (2) Rulebase được
  lắp ráp theo đúng thứ tự PAN-OS đánh giá thật trên firewall quản lý (Shared-PRE → DG-chain-PRE
  → DG-chain-POST → Shared-POST), mọi logic "rule đứng trước/rule đầu tiên" chạy trên danh sách
  đã lắp ráp này; (3) Live Match và Rule Hit Count bắt buộc thêm `target=<serial firewall>`, tự
  vô hiệu hóa im lặng nếu thiếu; (4) Zone awareness đổi nguồn từ Interface/Zone trong vsys sang
  Template của Target Firewall, cùng nguyên tắc tự vô hiệu nếu thiếu Target; (5) Candidate-config
  workflow thêm cảnh báo 2 tầng commit (Commit-to-Panorama + Commit-and-Push); (6) CHECK IP/CHECK
  AUDIT thêm 1 cột output bắt buộc "Vi tri Rule" (Shared-PRE/`<DG>`-PRE/`<DG>`-POST/Shared-POST)
  vì không còn 1 vsys duy nhất để ngầm định; (7) giới hạn mới ghi nhận: không tool nào xét được
  rule cấu hình cục bộ trực tiếp trên firewall (ngoài tầm quản lý Panorama).