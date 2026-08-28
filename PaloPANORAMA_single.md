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
| **3 hình thái output mỗi lần bàn giao** | (1) File/package cấu phần đã sửa. (2) 1 file `.py` duy nhất (`PaloRuleSearchSuite_single.py`). (3) File `.md` này, cập nhật mục XIV. |

## I.2–I.8

**Toàn bộ kiến trúc ghép 3 tool (lý do không gộp phẳng, cấu trúc thư mục 2 package `check_rule/`
+ `check_ip/` (+ `check_audit/` — Phần IV), quy tắc relative import, kỹ thuật đóng gói file
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

## IV.3. Giao diện — 5 khung

**Khung 1**: đổi `Management IP` → `Panorama IP`; thêm dropdown **Device Group** (bắt buộc, thay
cho việc audit ngầm định "vsys hiện tại"); thêm ô **Target Firewall (Serial)** không bắt buộc
(ảnh hưởng Rule Hit Count + độ chính xác so Zone ở shadow-check, 0.7/IV.2.3). Khung 2/3/4/5 —
**không đổi**, chỉ Khung 4 (bảng kết quả) thêm 1 cột **"Vi tri Rule"** như IV.1.

## IV.4. Luồng Import → popup xác nhận xoá — không đổi trình tự D5/D6/D9, chỉ đổi bước dựng xpath

Bước 4 (`delete_rule_candidate()`): xpath nay dựng theo cột **"Vi tri Rule"** đọc được từ file
Import (0.8) — trỏ đúng `pre-rulebase` hoặc `post-rulebase` của đúng Device Group, hoặc Shared
tương ứng. Bước 5 (cảnh báo cuối) **đổi nội dung theo 0.4**: nhấn mạnh 2 tầng commit (Panorama →
Push), không chỉ 1 tầng như bản Firewall gốc.

## IV.5. Định dạng Export/Import — 15 cột (thêm 1 so với bản gốc)

Giữ nguyên toàn bộ 14 cột gốc + style (font Times New Roman 11, header teal-blue `FF0D7377`,
data trắng, viền `FFC9C9C9`, `same_action=False` → chữ Action đỏ đậm, TEXT format `@`, AutoFilter
+ freeze header, CSV `utf-8-sig`). **Thêm cột thứ 15 "Vi tri Rule"** ngay sau "Name Rule" (giá trị
Shared-PRE/`<DG>`-PRE/`<DG>`-POST/Shared-POST) — bắt buộc cho Import (IV.4). `parse_import_file()`
nay bắt buộc đủ 3 cột `Name Rule` + `Loại (Finding Type)` + `Vi tri Rule` (thiếu → raise lỗi rõ
ràng, giữ nguyên nguyên tắc validate nghiêm ngặt của bản gốc chỉ mở rộng thêm 1 cột bắt buộc).

## IV.6. `pan_api.py` — API rules bắt buộc (bản Panorama)

1. `delete_rule_candidate(panorama_ip, api_key, devicegroup, rulebase, rule_name, verify_ssl)` —
   KHÔNG request nào chứa `type=commit` — giữ nguyên.
2. `fetch_rule_hit_count(panorama_ip, api_key, target_serial, verify_ssl, log_func)` — bắt buộc
   `target_serial`; thiếu → trả `{}` ngay không gọi API (0.7); lỗi/không hỗ trợ → log cảnh báo +
   `{}` — giữ nguyên D10.
3. `get_devicegroup_list()` / `resolve_devicegroup_chain(dg_name)` (thay `get_vsys_list()`) /
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

---

# PHẦN V — NGUYÊN TẮC BẢO TRÌ CHUNG

**Không đổi** so với bản gốc: quy tắc "chỉ sửa file cấu phần cần action" (bảng V.1), checklist
bàn giao sau mỗi lần fix (V.2), checklist nhanh khi tiếp nhận bảo trì (V.3) — áp dụng nguyên văn,
chỉ thêm 1 dòng vào checklist V.3: **"Sửa gì liên quan tới nguồn dữ liệu Panorama (xpath, chuỗi
Device Group, target)? → đọc lại PHẦN 0 trước khi sửa, đảm bảo không phá vỡ nguyên tắc lắp ráp
0.3 hoặc thừa kế object 0.2."**

---

# PHẦN XIV — NHẬT KÝ THAY ĐỔI GẦN NHẤT

> Chỉ liệt kê ngắn gọn. Chi tiết luật nghiệp vụ đã có sẵn ở Phần 0/II/III/IV — không lặp lại.

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