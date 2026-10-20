# -*- coding: utf-8 -*-
import csv
from dataclasses import dataclass
from typing import List, Optional
import openpyxl

from .core import (split_multi_value, split_ip_tokens, parse_ip_token,
                    parse_port_token, detect_protocol)

SRC_ALIASES = {'source ip', 'src ip', 'sourceip', 'srcip', 'source', 'src'}
DST_ALIASES = {'destination ip', 'dest ip', 'dst ip', 'destinationip', 'destip', 'dstip',
               'destination', 'dest', 'dst'}
PORT_ALIASES = {'port', 'dest port', 'destination port', 'dport', 'ports'}
PROTO_ALIASES = {'protocol', 'proto'}


@dataclass
class RequestRow:
    row_number: int
    source_tokens: List[dict]
    dest_tokens: List[dict]
    port_tokens: List[tuple]
    extra_values: List
    raw_source: str
    raw_dest: str
    raw_port: str


@dataclass
class ParsedRequestFile:
    headers: List[str]
    col_source_idx: int
    col_dest_idx: int
    col_port_idx: int
    col_protocol_idx: Optional[int]
    rows: List[RequestRow]


def _match_header(headers: List[str]):
    lower = [h.strip().lower() if h else '' for h in headers]
    col_source = col_dest = col_port = col_proto = None
    for i, h in enumerate(lower):
        if col_source is None and h in SRC_ALIASES:
            col_source = i
        elif col_dest is None and h in DST_ALIASES:
            col_dest = i
        elif col_port is None and h in PORT_ALIASES:
            col_port = i
        elif col_proto is None and h in PROTO_ALIASES:
            col_proto = i
    return col_source, col_dest, col_port, col_proto


def _read_xlsx_rows(path: str) -> List[List]:
    wb = openpyxl.load_workbook(path, data_only=True)
    ws = wb.worksheets[0]
    return [list(row) for row in ws.iter_rows(values_only=True)]


def _read_csv_rows(path: str) -> List[List]:
    rows = []
    with open(path, 'r', encoding='utf-8-sig', newline='') as f:
        sample = f.read(4096)
        f.seek(0)
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=',;\t')
        except Exception:
            dialect = csv.excel
        reader = csv.reader(f, dialect)
        for r in reader:
            rows.append(list(r))
    return rows


def parse_request_file(path: str) -> ParsedRequestFile:
    lower_path = path.lower()
    raw_rows = _read_csv_rows(path) if lower_path.endswith('.csv') else _read_xlsx_rows(path)
    raw_rows = [r for r in raw_rows if any(c is not None and str(c).strip() != '' for c in r)]
    if not raw_rows:
        raise ValueError("File request khong co du lieu.")

    header_row = raw_rows[0]
    col_source, col_dest, col_port, col_proto = _match_header([str(h) if h is not None else '' for h in header_row])

    if col_source is None or col_dest is None or col_port is None:
        col_source, col_dest, col_port = 0, 1, 2
        col_proto = 3 if len(header_row) > 3 else None
        headers = [f"Cot {i+1}" for i in range(len(header_row))]
        headers[0], headers[1], headers[2] = 'Source IP', 'Dest IP', 'Port'
        data_rows = raw_rows
    else:
        headers = [str(h) if h is not None else '' for h in header_row]
        data_rows = raw_rows[1:]

    rows: List[RequestRow] = []
    for i, r in enumerate(data_rows):
        r = list(r) + [None] * (len(headers) - len(r))
        raw_source = r[col_source] if col_source < len(r) else ''
        raw_dest = r[col_dest] if col_dest < len(r) else ''
        raw_port = r[col_port] if col_port < len(r) else ''

        if (raw_source is None or str(raw_source).strip() == '') and \
           (raw_dest is None or str(raw_dest).strip() == ''):
            continue

        row_protocol = None
        if col_proto is not None and col_proto < len(r) and r[col_proto]:
            row_protocol = detect_protocol(str(r[col_proto]))

        source_tokens = [parse_ip_token(t) for t in split_ip_tokens(raw_source)]
        dest_tokens = [parse_ip_token(t) for t in split_ip_tokens(raw_dest)]

        port_tokens = []
        for t in split_multi_value(raw_port):
            proto_hint = detect_protocol(t) or row_protocol
            pr = parse_port_token(t)
            if pr is not None:
                port_tokens.append((pr[0], pr[1], proto_hint))

        extra_values = [r[j] for j in range(len(headers))]

        rows.append(RequestRow(
            row_number=i + 2,
            source_tokens=source_tokens,
            dest_tokens=dest_tokens,
            port_tokens=port_tokens,
            extra_values=extra_values,
            raw_source='' if raw_source is None else str(raw_source),
            raw_dest='' if raw_dest is None else str(raw_dest),
            raw_port='' if raw_port is None else str(raw_port),
        ))

    return ParsedRequestFile(headers=headers, col_source_idx=col_source, col_dest_idx=col_dest,
                              col_port_idx=col_port, col_protocol_idx=col_proto, rows=rows)


def build_manual_request(table_rows: List[List[str]]) -> ParsedRequestFile:
    headers = ['Source IP', 'Dest IP', 'Port']
    rows: List[RequestRow] = []
    for i, (src, dst, prt) in enumerate(table_rows):
        src, dst, prt = (src or '').strip(), (dst or '').strip(), (prt or '').strip()
        if not src and not dst and not prt:
            continue
        source_tokens = [parse_ip_token(t) for t in split_ip_tokens(src)]
        dest_tokens = [parse_ip_token(t) for t in split_ip_tokens(dst)]
        port_tokens = []
        for t in split_multi_value(prt):
            proto_hint = detect_protocol(t)
            pr = parse_port_token(t)
            if pr is not None:
                port_tokens.append((pr[0], pr[1], proto_hint))
        rows.append(RequestRow(
            row_number=i + 2,
            source_tokens=source_tokens, dest_tokens=dest_tokens, port_tokens=port_tokens,
            extra_values=[src, dst, prt],
            raw_source=src, raw_dest=dst, raw_port=prt,
        ))
    return ParsedRequestFile(headers=headers, col_source_idx=0, col_dest_idx=1, col_port_idx=2,
                              col_protocol_idx=None, rows=rows)