"""时区与时间段工具。"""
from __future__ import annotations

import re
from datetime import datetime, time
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .errors import ValidationError

_HHMM = re.compile(r"^(\d{1,2}):(\d{2})$")


def resolve_timezone(tz_name: str | None, ancestor_tz: str | None) -> str:
    """节点未设时区时沿用最近祖先；都没有则为 UTC。"""
    return tz_name or ancestor_tz or "UTC"


def validate_timezone(tz_name: str) -> None:
    try:
        ZoneInfo(tz_name)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise ValidationError(f"未知时区: {tz_name!r}") from exc


def parse_hhmm(text: str) -> time:
    m = _HHMM.match(text.strip())
    if not m:
        raise ValidationError(f"非法时间: {text!r}")
    hour, minute = int(m.group(1)), int(m.group(2))
    if hour > 23 or minute > 59:
        raise ValidationError(f"非法时间: {text!r}")
    return time(hour, minute)


def validate_time_range(start: str, end: str) -> None:
    """保存时校验：格式合法且起止不能相同。"""
    if parse_hhmm(start) == parse_hhmm(end):
        raise ValidationError(f"时间段起点和终点不能相同: {start!r}-{end!r}")


def local_time_in_range(moment: datetime, tz_name: str, start: str, end: str) -> bool:
    """判断 moment 在 tz_name 时区下的当地时间是否落在 [start, end)。

    start > end 表示跨午夜。夏令时回拨时重复出现的钟点都算（两个 fold 各自
    对应不同的 UTC 时刻，分别命中即可）；拨快时跳过的钟点不存在，自然不会命中。
    """
    local = moment.astimezone(ZoneInfo(tz_name))
    t = local.time().replace(tzinfo=None)
    s, e = parse_hhmm(start), parse_hhmm(end)
    if s < e:
        return s <= t < e
    return t >= s or t < e
