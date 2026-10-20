# testlab — Môi trường chạy thử TOÀN BỘ tính năng bản PANORAMA (không cần Panorama thật)

Thư mục này là **phòng lab đóng gói sẵn**: một con **Panorama giả lập** nói đúng XML API mà
tool đang gọi, kèm cấu hình mẫu nhiều Device Group + Template và file input mẫu được thiết kế
để **chạm vào mọi tính năng của cả 3 tab**. Mục đích: bật lên là test được ngay, không cần
thiết bị thật, không đụng vào production.

Khác với bản Firewall standalone, lab này còn chốt luôn **8 điểm đặc thù Panorama** (0.1 → 0.8):

| Mã | Điểm đặc thù Panorama được lab chốt |
|---|---|
| 0.1 | Đọc danh sách **Device Group** + danh sách **thiết bị (serial/hostname)** qua op-command |
| 0.2 | Object **thừa kế theo chuỗi DG** (`shared → DG-ALL → DG-DC → DG-HN`), DG gần đè DG xa |
| 0.3 | Rulebase **lắp ráp 6 bước** (Shared-PRE → DG-PRE từ tổ tiên xuống → DG-POST **đảo chiều** → Shared-POST), mỗi rule có nhãn **Vi tri Rule** |
| 0.4 | **Candidate config** đọc theo cấu trúc DG + cảnh báo **2 TẦNG COMMIT** (Panorama còn cần *Commit and Push*) |
| 0.5 | **Live Match** (`test security-policy-match`) chạy trên dataplane firewall → **BẮT BUỘC** `target=<serial>`; thiếu Target thì **bỏ qua, không gọi API** |
| 0.6 | **Zone lấy từ Template/Template Stack** của đúng Target Firewall; không có Target thì cảnh báo Zone **tự vô hiệu, im lặng** |
| 0.7 | **Rule Hit Count** (Policy Optimizer) cũng bắt buộc `target=<serial>`; khoá theo `(tên rule, Vi tri Rule)` — hai DG được phép trùng tên rule (D9) |
| 0.8 | Lệnh ghi (DISABLE/DELETE) dùng **xpath pre/post-rulebase của đúng Device Group**, và **TUYỆT ĐỐI không commit** (D6) |

---

## 1. Chạy nhanh nhất — nghiệm thu tự động (1 lệnh)

```bash
python testlab/run_all_features.py --auto
```

Lệnh này tự bật Panorama giả lập, chạy **đúng các hàm mà GUI gọi** (cùng pipeline, cùng
exporter), đối chiếu với kỳ vọng rồi in bảng PASS/FAIL, cuối cùng tự tắt server.

```
  TONG KET: 68/68 PASS
  File ket qua: testlab/output
```

Exit code `0` = tất cả PASS, `1` = có FAIL (dùng được cho CI / pre-release).

Toàn bộ kịch bản này cũng được nối vào bộ test chung, nên chỉ cần:

```bash
python -m unittest discover -s tests -q      # 221 test (220 unit + 1 case gói trọn 68 kiểm tra nghiệm thu)
```

---

## 2. Chạy GUI thật trên Panorama giả lập

**Cửa sổ 1** — bật Panorama giả lập:

```bash
python testlab/mock_panorama_api.py
```

**Cửa sổ 2** — mở tool:

```bash
python PaloPANORAMA_single.py        # hoặc file .exe đã build từ chính file này
```

Nhập vào GUI (cả 3 tab đều dùng chung thông tin này):

| Trường | Giá trị |
|---|---|
| **Panorama IP** | `127.0.0.1:8443` |
| **API Key** | bất kỳ chuỗi nào, ví dụ `testlab` |
| **Kiểm tra SSL Certificate** | **KHÔNG tick** (cert tự ký) |
| **Device Group** | `DG-HN` (chọn `DG-ALL` / `DG-DC` để thấy phạm vi đổi theo) |
| **Target Firewall (Serial)** | `001122334455  (FW-HN-01)` |

> Tool luôn gọi `https://<Panorama IP>/api/` nên gõ kèm `:8443` là chạy được,
> **không cần quyền admin** để chiếm cổng 443.

**Thử luôn 2 trạng thái của Target** (đây là điểm khác bản standalone nhiều nhất):

- **Có Target** → Live Match (0.5), Zone từ Template (0.6) và Hit Count (0.7) đều hoạt động.
- **Bỏ trống Target** → cả 3 thứ trên **tự vô hiệu, không gọi API, không báo lỗi đỏ**;
  tool vẫn chạy đủ phần LOCAL. Panorama giả lập **từ chối** mọi op-command dataplane
  thiếu `target=` (đúng như Panorama thật), nên nếu tool quên truyền `target` là lộ ra ngay.

### Tab CHECK RULE
Chọn file `testlab/samples/request_check_rule.xlsx` → bấm **Check**.
Cột "Ghi chu (ky vong)" trong chính file đó ghi sẵn mỗi dòng phải ra tier nào.
File xuất ra có thêm cột **Vi tri Rule** (nằm ngay sau "Name Rule") — đây là cột chỉ bản
Panorama mới có, cho biết rule nằm ở Shared hay DG nào, pre hay post.

### Tab CHECK IP
- Mục 2: dán nội dung `testlab/samples/ip_list.txt`
- Mục 3 (tuỳ chọn): Import `testlab/samples/traffic_log.xlsx`
- Mục 4: chọn **Yes (Full)** hoặc **No + nhập IP** để thử Export NAT
- Bấm **Check / Export** → nhập cả 2 mục thì ra **1 file 2 sheet** (`Security Rules` + `NAT Rules`)
- Bỏ trống cả 2 mục → tool **chặn lại và nói rõ cần nhập gì** (không chạy rỗng)

### Tab CHECK AUDIT
Tick cả 3 tính năng → **Check** → **Export** → thử **Import**.
Mọi lệnh ghi (`set`/`delete`) chỉ được **ghi vào `testlab/.journal.log`**, server
**không bao giờ sửa file cấu hình** — chạy lại bao nhiêu lần cũng ra kết quả như nhau.
Nếu tool lỡ gọi `commit`, server **từ chối** và ghi cảnh báo vào journal (đúng luật D6 —
trên Panorama càng nguy hiểm vì còn một tầng *Commit and Push* xuống firewall).

---

## 3. Cấu hình mẫu được thiết kế để chạm vào cái gì

`fixtures/running_config.xml` — hệ Panorama 3 Device Group lồng nhau
(`DG-ALL` → `DG-DC` → `DG-HN`), 1 Template `TPL-BASE` + 1 Template Stack `STACK-HN`,
2 thiết bị (`001122334455` = FW-HN-01, `009988776655` = FW-HN-02),
**13 security rule** rải đủ 4 vị trí + **2 NAT rule**:

| Vi tri Rule | Rule | Dùng để test |
|---|---|---|
| Shared-PRE | `S00-BLOCK-BADNET` (deny) | **SHADOW**: rule deny ở Shared chặn trước mọi rule DG |
| DG-ALL-PRE | `A01-WIDE-SUBNET` | **wide_full_match** (cover qua subnet rộng), thừa kế xuống mọi DG con |
| DG-DC-PRE | `D01-RANGE-TO-DB` | **TOP1** qua object `ip-range` **thừa kế từ DG cha** |
| DG-DC-PRE | `D02-RANGE-UNION` | range phủ kín bởi **HỢP 2 object** liền kề |
| DG-DC-PRE | `D03-ZONE-GAP` | cảnh báo **thiếu Zone** (Zone đọc từ Template của Target) |
| DG-DC-PRE | `D03B-ZONE-ANY-OK` | chốt **fix `_zones_cover`**: `D03` chỉ `trust→untrust` **không được** coi là che rule này (zone `any`) |
| DG-HN-PRE | `H01-APP-TO-DB` | **TOP1** FULL MATCH + **LIVE_MATCH** khi có Target |
| DG-HN-PRE | `H02-APP-TO-WEB` | **TOP1.1** (chỉ thiếu Port) |
| DG-HN-PRE | `H03-ALLOW-BADNET-ANYWAY` | khớp rule nhưng bị `S00` (Shared-PRE) deny chặn trước → chứng minh thứ tự 0.3 |
| DG-HN-POST | `H90-SHADOWED-NOHIT` | tab AUDIT: **Shadow** thật (bị rule DG-HN-PRE che) + 0 hit → Import = **DISABLE** |
| DG-DC-POST | `D90-DISABLED-NOHIT` | tab AUDIT: **Disabled** → Import = **DELETE** |
| DG-ALL-POST | `A90-DGALL-POST-NOHIT` | chứng minh DG-POST **đảo chiều** (DG-ALL-POST xếp SAU DG-HN-POST) |
| Shared-POST | `S99-ANY-ANY-ANY` | tab AUDIT: **Overly Permissive** (chỉ Export, không bao giờ tự xoá) |

NAT: `NAT01-OUTBOUND-HIDE` ở **DG-HN pre-rulebase** (dynamic-ip-and-port) và
`NAT02-INBOUND-DNAT` ở **DG-HN post-rulebase** (destination-translation) — để chốt
NAT cũng được lắp ráp + gắn nhãn Vi tri Rule theo đúng cơ chế 0.3.

Ngoài ra còn: object `shared` bị object cùng tên của **DG con đè** (0.2), group lồng group,
Dynamic Address Group (`GR-DAG` + registered-ip), FQDN, service group, nhánh `<readonly>`
chứa bản sao `parent-dg` (để chốt tool **không** nhầm lấy bản readonly), và Template Stack
trỏ về `TPL-BASE` (để chốt việc suy Zone đi qua stack).

`fixtures/candidate_config.xml` = running + 1 object + 1 rule **chưa commit** → dùng để
thử lớp cảnh báo **CANDIDATE CONFIG** + nhắc 2 tầng commit của Panorama.

**Quy ước đặt tên:** rule có tên kết thúc bằng `-NOHIT` sẽ được Panorama giả lập trả về
**0 hit** (tạo 200 ngày trước) → kích hoạt nhánh UNUSED. Các rule khác có hit gần đây.
Response `rule-hit-count` được trả về **lồng đúng cây** `device-group|shared` +
`pre|post-rulebase`, nên tool buộc phải tự suy `Vi tri Rule` từ chính response (D9).

---

## 4. Một giới hạn API đã biết (lab chốt luôn cách suy giảm)

Tool gọi `show rule-hit-count` bằng **4 lệnh chi phí cố định**: Device Group (wildcard)
pre/post **+ Shared** pre/post. Nhánh **Shared là best-effort**: nếu một bản Panorama
không nhận node `<shared>` cho lệnh này, nó sẽ bị từ chối — khi đó tool **chỉ log cảnh báo
và đi tiếp**, rule trong Device Group vẫn có hit-count đầy đủ (nhánh UNUSED chỉ không áp
dụng cho rule Shared). Case `0.7 - Panorama tu choi pham vi <shared>` trong
`run_all_features.py` mô phỏng đúng tình huống đó và chốt rằng tool **không raise, không
trả rỗng**. Bỏ nhánh Shared đi thì rule Shared sẽ **vĩnh viễn không bao giờ** có hit-count,
nên lab giữ nhánh này.

---

## 5. Muốn thử cấu hình Panorama của chính mình?

```bash
python testlab/mock_panorama_api.py --config /duong/dan/panorama-running-config.xml \
                                    --candidate /duong/dan/candidate.xml
```

Lấy file thật bằng: **Panorama → Setup → Operations → Export named configuration snapshot**,
hoặc `curl -k "https://<panorama>/api/?type=config&action=show&key=<KEY>&xpath=/config"`.

Sinh lại file input mẫu: `python testlab/make_samples.py`

---

## 6. Những gì lab này **không** thay thế được

- Hiệu năng/độ trễ thật của Panorama (lab trả lời tức thì; Panorama thật chậm hơn nhiều
  khi config lớn, nhất là `action=show` toàn bộ `/config`).
- Khác biệt theo phiên bản PAN-OS/Panorama (lab bám theo tài liệu XML API).
- `test security-policy-match` và `rule-hit-count` ở lab là **mô phỏng** theo thứ tự rule
  trong file config — rất sát nhưng không phải dataplane/Policy Optimizer thật.
- Tầng **Commit and Push** xuống firewall: lab cố tình **không** mô phỏng, vì tool không
  bao giờ được phép gọi commit.

Nói cách khác: lab chốt được phần **logic + luồng API + đặc thù Panorama**. Phần **tương
thích thiết bị** vẫn cần một lần chạy thử trên Panorama thật (chỉ cần đọc, không ghi)
trước khi phát hành.
