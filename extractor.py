"""安全解压核心。

威胁模型：压缩包来自外部、不可信，需要防
1. 路径越界（zip-slip、绝对路径、.. 穿越）
2. 符号链接 / 硬链接指向包外文件
3. 设备文件、FIFO 等特殊文件
4. 解压炸弹（按实际写出字节限流，不靠压缩包自报大小）
5. 条目数爆炸

原则：不调用任何库的“一键解压”，每个条目手工校验、手工流式写出。
"""
from __future__ import annotations

import os
import posixpath
import stat
import tarfile
import zipfile
from dataclasses import dataclass
from pathlib import Path

from config import Config


class UnsafeArchiveError(Exception):
    """压缩包内容不安全或超出限制时抛出。"""


@dataclass
class ExtractResult:
    kind: str
    entries: int
    bytes_written: int


class _Accounter:
    """累计实际写出字节，所有限额以这里为准，不信任压缩包头里的声明。"""

    def __init__(self, total_limit: int):
        self.bytes_left = total_limit
        self.written = 0

    def take(self, n: int) -> None:
        if n > self.bytes_left:
            raise UnsafeArchiveError(
                f"解压后总大小超限（上限 {self._mb(self.bytes_left + self.written)} MB）"
            )
        self.bytes_left -= n
        self.written += n

    @staticmethod
    def _mb(n: int) -> str:
        return f"{n / 1024 / 1024:.1f}"


def _is_within(base: Path, target: Path) -> bool:
    """realpath 之后 target 仍在 base 目录内。"""
    try:
        target.resolve(strict=False).relative_to(base)
        return True
    except ValueError:
        return False


def _safe_target(base: Path, member_name: str) -> Path | None:
    """把条目名映射到 base 内的安全路径，任何越界情况直接拒绝。"""
    if not member_name or "\x00" in member_name:
        raise UnsafeArchiveError("条目名为空或非法")
    # Windows 压缩包常用反斜杠，统一成正斜杠再校验
    name = member_name.replace("\\", "/")
    if name.startswith("/"):
        raise UnsafeArchiveError(f"拒绝绝对路径条目: {member_name}")
    if len(name) >= 2 and name[1] == ":" and name[0].isalpha():
        raise UnsafeArchiveError(f"拒绝带盘符的路径: {member_name}")
    # 统一按 posix 规则做词法规范化
    normalized = posixpath.normpath(name)
    parts = [p for p in normalized.split("/") if p not in ("", ".")]
    if not parts:
        return None
    if any(p == ".." for p in parts):
        raise UnsafeArchiveError(f"路径越界（含 ..）: {member_name}")
    target = base.joinpath(*parts)
    if not _is_within(base, target):
        raise UnsafeArchiveError(f"路径越界: {member_name}")
    return target


def _stream_copy(src, dst, per_file_limit: int, acc: _Accounter) -> int:
    written = 0
    while True:
        chunk = src.read(1024 * 1024)
        if not chunk:
            break
        written += len(chunk)
        if written > per_file_limit:
            raise UnsafeArchiveError(
                f"单文件超限（上限 {per_file_limit / 1024 / 1024:.0f} MB）"
            )
        # 总限额在真正写盘前扣减
        acc.take(len(chunk))
        dst.write(chunk)
    return written


def _check_duplicate(target: Path) -> None:
    if target.exists() or target.is_symlink():
        raise UnsafeArchiveError(f"条目路径冲突（可能重复写入）: {target.name}")


def _ratio_ok(declared_size: int, compressed_size: int, max_ratio: int) -> bool:
    if compressed_size <= 0:
        return True
    return declared_size <= compressed_size * max_ratio


def _extract_zip(
    archive_path: Path, dest: Path, cfg: Config, progress
) -> ExtractResult:
    total_limit = cfg.max_total_mb * 1024 * 1024
    file_limit = cfg.max_file_mb * 1024 * 1024
    acc = _Accounter(total_limit)
    base = dest.resolve()
    written_entries = 0

    with zipfile.ZipFile(archive_path) as zf:
        infos = zf.infolist()
        if len(infos) > cfg.max_entries:
            raise UnsafeArchiveError(f"条目数超限（上限 {cfg.max_entries}）")
        total = len(infos)

        for index, info in enumerate(infos, start=1):
            target = _safe_target(base, info.filename)
            if target is None:
                progress(index, total, info.filename)
                continue

            mode = info.external_attr >> 16
            if stat.S_ISLNK(mode):
                raise UnsafeArchiveError(f"拒绝符号链接条目: {info.filename}")
            # writestr 产生的条目只有权限位（0o600）、没有类型位，按普通文件处理
            fmt = stat.S_IFMT(mode)
            if fmt and not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
                raise UnsafeArchiveError(f"拒绝特殊文件类型: {info.filename}")

            # 包头声明的大小只用来提前拒绝，真正的限额在流式写出时执行
            if info.file_size > file_limit:
                raise UnsafeArchiveError(
                    f"单文件超限（上限 {cfg.max_file_mb} MB）: {info.filename}"
                )
            if not _ratio_ok(info.file_size, info.compress_size, cfg.max_ratio):
                raise UnsafeArchiveError(
                    f"压缩比超 {cfg.max_ratio}:1，疑似解压炸弹: {info.filename}"
                )

            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                _check_duplicate(target)
                target.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(info) as src, open(target, "wb") as fh:
                    _stream_copy(src, fh, file_limit, acc)
                os.chmod(target, 0o644)  # 忽略压缩包里带来的可执行/setuid 位
                written_entries += 1

            progress(index, total, info.filename)

    return ExtractResult("zip", written_entries, acc.written)


def _extract_tar(
    archive_path: Path, dest: Path, cfg: Config, progress
) -> ExtractResult:
    total_limit = cfg.max_total_mb * 1024 * 1024
    file_limit = cfg.max_file_mb * 1024 * 1024
    acc = _Accounter(total_limit)
    base = dest.resolve()
    written_entries = 0

    with tarfile.open(archive_path) as tf:
        members = tf.getmembers()
        if len(members) > cfg.max_entries:
            raise UnsafeArchiveError(f"条目数超限（上限 {cfg.max_entries}）")
        total = len(members)

        for index, m in enumerate(members, start=1):
            target = _safe_target(base, m.name)
            if target is None:
                progress(index, total, m.name)
                continue

            # 软链、硬链一律拒绝，防止借链接读写包外文件
            if m.issym() or m.islnk():
                raise UnsafeArchiveError(f"拒绝链接条目: {m.name}")
            # 设备、FIFO 等非普通文件一律拒绝
            if not (m.isdir() or m.isfile()):
                raise UnsafeArchiveError(f"拒绝特殊文件类型: {m.name}")
            if m.size > file_limit:
                raise UnsafeArchiveError(
                    f"单文件超限（上限 {cfg.max_file_mb} MB）: {m.name}"
                )

            if m.isdir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                _check_duplicate(target)
                target.parent.mkdir(parents=True, exist_ok=True)
                src = tf.extractfile(m)
                if src is None:
                    raise UnsafeArchiveError(f"无法读取条目: {m.name}")
                with src, open(target, "wb") as fh:
                    _stream_copy(src, fh, file_limit, acc)
                os.chmod(target, 0o644)
                written_entries += 1

            progress(index, total, m.name)

    return ExtractResult(
        "tar" if str(archive_path).endswith(".tar") else "tar.gz",
        written_entries,
        acc.written,
    )


def detect_kind(archive_path: Path) -> str:
    """按文件头魔数判断类型，不信任上传文件名。"""
    with open(archive_path, "rb") as fh:
        head = fh.read(512)
    if head[:4] == b"PK\x03\x04" or head[:4] == b"PK\x05\x06":
        return "zip"
    if head[:2] == b"\x1f\x8b":  # gzip
        return "tar"
    if head[:6] == b"\xfd7zXZ\x00":  # xz
        return "tar"
    if head[:3] == b"BZh":  # bzip2
        return "tar"
    if len(head) >= 265 and b"ustar" in head[257:263]:  # 裸 tar
        return "tar"
    raise UnsafeArchiveError("不支持的压缩格式（仅支持 zip / tar / tar.gz / tar.xz / tar.bz2）")


def extract_archive(
    archive_path: Path, dest_dir: Path, cfg: Config, progress
) -> ExtractResult:
    """入口：dest_dir 必须是本次任务独占的空目录。"""
    kind = detect_kind(archive_path)
    dest_dir.mkdir(parents=True, exist_ok=True)
    if kind == "zip":
        return _extract_zip(archive_path, dest_dir, cfg, progress)
    return _extract_tar(archive_path, dest_dir, cfg, progress)
