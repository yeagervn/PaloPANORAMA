# PaloPANORAMA Suite — bộ 3 tool rà soát Security Policy trên **Panorama**

Bản Panorama của [PaloRuleSearch Suite](https://github.com/yeagervn/PaAIO_StandAlone).
Cùng 3 tool, cùng luật nghiệp vụ, nhưng nói chuyện với **Panorama** thay vì
từng firewall rời — nghĩa là phải xử lý Device Group, thừa kế object, thứ tự
lắp ráp rulebase 6 bước, và `target=` bắt buộc cho mọi lệnh dataplane.

| Tab | Trả lời câu hỏi gì | Package |
|---|---|---|
| **CHECK RULE** | "Request mở port này đã có rule nào cho phép chưa? Nếu chưa thì tạo mới hay chỉ bổ sung Source/Dest/Port vào rule có sẵn?" | `check_rule_pan/` |
| **CHECK IP** | "IP này nằm trong những rule nào? Traffic trong file log thật sự đang được rule nào cho qua?" | `check_ip_pan/` |
| **CHECK AUDIT** | "Rulebase có rule rác không: bị che khuất (shadow), đang tắt, hay quá rộng (Any)?" | `check_audit_pan/` |

---

## 8 điểm khác bản Firewall standalone

Đây là phần **phải đọc trước** khi sửa bất cứ thứ gì — chi tiết ở
[`PaloPANORAMA_single.md`](PaloPANORAMA_single.md) PHẦN 0.

| # | Điểm | Nghĩa là gì |
|---|---|---|
| 0.1 | Đối tượng kết nối | Panorama, không phải firewall. Chọn **Device Group**, không phải VSYS |
| 0.2 | Thừa kế object | Object nạp theo **chuỗi DG cha → con**, DG sau đè DG trước (thay cho "shared trước, vsys đè sau") |
| 0.3 | Thứ tự đánh giá rule | Lắp ráp 6 bước: Shared-PRE → DG-chain-PRE → **rule cục bộ firewall** → DG-chain-POST → Shared-POST |
| 0.4 | Candidate config | Panorama có thêm tầng *Commit and Push* — tool **không bao giờ** gọi commit |
| 0.5 | Live Match | `test security-policy-match` **bắt buộc `target=<serial>`**, và vsys thật của thiết bị đó |
| 0.6 | Zone | Lấy từ **Template** gắn với serial, không phải Interface/Zone trong vsys |
| 0.7 | Hit Count | `show rule-hit-count` **bắt buộc `target=`**, tính theo **từng firewall** |
| 0.8 | Xpath ghi | Ghi theo DG, khác hẳn xpath của firewall rời |

---

## Chạy

```bash
pip install requests openpyxl          # 2 thư viện ngoài duy nhất
python PaloPANORAMA_single.py          # mở Suite 3 tab
```

Bản phát hành là **một file duy nhất** `PaloPANORAMA_single.py` — 3 package
được nén zip và nhúng base64, lúc chạy tự giải mã trong RAM.

```bash
python tools/build_panorama_single.py          # sinh lại file gộp từ 3 package
python tools/build_panorama_single.py --check  # KHÔNG ghi gì, chỉ báo lệch: exit 0 = đồng bộ, 1 = source mới hơn
python -m py_compile PaloPANORAMA_single.py
pyinstaller --onefile --noconsole --name PaloPANORAMASuite PaloPANORAMA_single.py
```

> ⚠️ **Không bao giờ sửa tay `PaloPANORAMA_single.py`.** Sửa trong
> `check_rule_pan/`, `check_ip_pan/`, `check_audit_pan/` rồi build lại. Thay đổi
> ở phần `main` (vd `on_close`) được đưa vào `_migrate_main()` của builder để
> file gộp luôn sinh lại được từ đầu. Trước khi commit, chạy `--check`: nó exit **1**
> nếu code rời mới hơn bản gộp — đúng lỗi bàn giao làm `.exe` phát hành ra chạy logic CŨ.
> Chính builder cũng có test riêng: `tests/test_build_panorama_single.py` (7 ca).

---

## Nguyên tắc an toàn xuyên suốt

| Nguyên tắc | Nghĩa là gì |
|---|---|
| **Chỉ đọc running-config** | Rule chưa commit/push thì chưa có hiệu lực — không dùng để kết luận "traffic đã được phép" |
| **Chỉ khớp CHÍNH XÁC mới được chấp nhận** | Không gợi ý "bổ sung vào rule có sẵn" nếu field đó là group rộng hơn input |
| **Không bao giờ commit** | Mọi lệnh ghi chỉ vào candidate. Trên Panorama còn nguy hiểm hơn vì có thêm tầng *Commit and Push* |
| **Thiếu `target=` thì dừng, không đoán** | Lab **cố tình** từ chối mọi op-command dataplane thiếu `target=` để lộ lỗi ngay |
| **Continue, not Crash** | Object không resolve được, thiếu thẻ XML → ghi log và đi tiếp |
| **Tkinter chỉ được chạm trên main thread** | Worker chỉ được đẩy việc qua `queue`. Có bộ quét AST trong test làm đỏ nếu ai vi phạm |

---

## Cây thư mục

```
check_rule_pan/   tool #1 — core, matcher, resolver, index, request, exporter, gui
check_ip_pan/     tool #2 — core, pan_api, resolver_engine, matching_engine, excel_export, gui
check_audit_pan/  tool #3 — core, pan_api, resolver, detectors, excel_io, gui
tools/
  build_panorama_single.py   nén 3 package → nhúng vào file gộp (idempotent, có --check)
tests/            243 test khi máy có Tk + Xvfb — unittest, không cần Panorama
testlab/          Panorama GIẢ LẬP + fixture + bộ nghiệm thu 68 ca
PaloPANORAMA_single.py   bản gộp 1 file (SINH TỰ ĐỘNG — đừng sửa tay)
PaloPANORAMA_single.md   TÀI LIỆU CHÍNH: PHẦN 0 (delta Panorama) + luật từng tool + nhật ký
require.md               spec gốc
```

---

## Kiểm thử — 2 tầng

```bash
# 1. Unit + E2E GUI (không cần Panorama thật)
# Con số phụ thuộc trình thông dịch — chỉ dòng cuối là nghiệm thu đầy đủ:
python3.13 -m unittest discover -s tests -q             # 231 test, skipped=5 (3.13 KHÔNG có tkinter)
python3.12 -m unittest discover -s tests -q             # 231 test, skipped=4 (có tkinter, thiếu $DISPLAY)
xvfb-run -a python3.12 -m unittest discover -s tests -q # 243 test, 0 skip  ← dùng con số này

# 2. Nghiệm thu toàn bộ tính năng trên Panorama giả lập
python testlab/run_all_features.py --auto             # 68/68 PASS
```

| Tầng | Phủ gì | KHÔNG phủ gì |
|---|---|---|
| `tests/` | Luật nghiệp vụ, 8 điểm đặc thù Panorama, vòng đời GUI, **E2E lái thật giao diện cả 3 tab** | Dataplane thật, Policy Optimizer thật |
| `testlab/` | Lớp gọi API thật qua HTTPS (cert tự ký), chuỗi DG, lắp ráp rulebase, `target=` bắt buộc, lệnh ghi candidate | Tầng GUI (gọi thẳng hàm pipeline) |

Hai tầng **cố tình** không phủ cùng một thứ: 3 lỗi lớn nhất tìm được gần đây
(Export NAT hỏng, Load Config hỏng, chế độ "Chọn file" mất trắng lượt chạy)
**vẫn PASS 68/68 ở `testlab/`** vì lab gọi thẳng pipeline, không qua giao diện.

Thông số trỏ GUI vào lab: `127.0.0.1:8443`, API Key bất kỳ, **bỏ tick** kiểm
tra SSL, Device Group `DG-HN`, Target `001122334455`.

---

## Tài liệu

| File | Nội dung |
|---|---|
| **[`PaloPANORAMA_single.md`](PaloPANORAMA_single.md)** | Tài liệu chính. **PHẦN 0** = 8 điểm delta Firewall → Panorama (đọc trước tiên). Mục *Tình trạng hiện tại* = SHA256 bản gộp, số test, đã kiểm chứng tới đâu / **CHƯA** tới đâu. PHẦN II/III/IV = luật từng tool. PHẦN V = quy tắc bảo trì. PHẦN VI = môi trường kiểm thử. PHẦN XIV = nhật ký |
| [`require.md`](require.md) | Spec gốc kèm các quyết định đã khoá |
| [`testlab/README.md`](testlab/README.md) | Cách bật Panorama giả lập và trỏ GUI vào nó |

---

## Hạn chế đã biết

- **Chưa chạy với Panorama THẬT.** Toàn bộ kiểm chứng dùng XML giả lập + mock
  HTTPS. Cần 1 lần chạy **chỉ đọc** trên thiết bị thật trước khi phát hành.
- **Chưa ai nhìn bố cục GUI trên Windows** — mọi kiểm chứng GUI headless qua Xvfb.
- **Schema `<shared>` của `show rule-hit-count`** chưa xác nhận trên thiết bị thật
  (best-effort có chủ đích: bị từ chối → log cảnh báo + đi tiếp).
- **Rule cục bộ trên firewall (0.3 bước 3)** chưa có đường nạp trong GUI.
- **Live Match / hit-count trong lab là mô phỏng**, không phải dataplane thật.
