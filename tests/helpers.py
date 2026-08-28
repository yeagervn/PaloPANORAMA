# -*- coding: utf-8 -*-
"""
Nhanh test: phu de nen (helpers) cho cac test cua check_audit.
"""

import ipaddress

from check_audit.core import RuleSnapshot, RuleHitStat
from check_audit.resolver import ResolvedAddr, ResolvedService


def ip_int(ip: str) -> int:
    return int(ipaddress.ip_address(ip))


def ra_any() -> ResolvedAddr:
    return ResolvedAddr(is_any=True)


def ra_host(ip: str) -> ResolvedAddr:
    n = ip_int(ip)
    return ResolvedAddr(ranges=[(n, n)])


def ra_range(start: str, end: str) -> ResolvedAddr:
    return ResolvedAddr(ranges=[(ip_int(start), ip_int(end))])


def ra_subnet(net: str) -> ResolvedAddr:
    net_obj = ipaddress.ip_network(net, strict=False)
    return ResolvedAddr(ranges=[(int(net_obj.network_address), int(net_obj.broadcast_address))])


def svc_any() -> ResolvedService:
    return ResolvedService(is_any=True)


def svc_ports(ports) -> ResolvedService:
    return ResolvedService(ports=list(ports))


def svc_app_default(apps) -> ResolvedService:
    return ResolvedService(is_app_default=True, applications=list(apps))


def mk_rule(index, name, action="allow", disabled=False, src=None, dst=None, svc=None,
            from_zones=None, to_zones=None, application=None, uuid=""):
    """Tao 1 RuleSnapshot da co resolved field (cho test detector truc tiep).
    `any`/empty -> resolved san (khong can resolver). Ten cu the -> de None,
    test phai `attach_resolved()` lai cho dung y nhu cac test khong can resolver."""
    r = RuleSnapshot(
        index=index, name=name, uuid=uuid,
        from_zones=list(from_zones or []), to_zones=list(to_zones or []),
        source=list(src or []), destination=list(dst or []),
        application=list(application or []), service=list(svc or []),
        action=action, disabled=disabled,
    )
    srcs, dsts, svcs = r.source, r.destination, r.service
    r.resolved_source = ra_any() if (not srcs or "any" in srcs) else None
    r.resolved_destination = ra_any() if (not dsts or "any" in dsts) else None
    r.resolved_service = svc_any() if (not svcs or "any" in svcs) else None
    return r


def attach_resolved(rule, src=None, dst=None, svc=None):
    if src is not None:
        rule.resolved_source = src
    if dst is not None:
        rule.resolved_destination = dst
    if svc is not None:
        rule.resolved_service = svc
    return rule


def hit_stat(hit_count=None, last_hit=None, creation=None):
    return RuleHitStat(hit_count, last_hit, creation)