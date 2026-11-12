"""任务目录管理、状态持久化与崩溃恢复。

每个任务完全独立的目录，互不串文件：
    data/jobs/<job_id>/
        archive.<ext>        上传的原始压缩包
        status.json          任务状态（原子写）
        extract/             解压工作目录（只有成功的任务才会保留内容）
        result.zip           成功后重新打包的结果，存在即代表可下载
"""
from __future__ import annotations

import fcntl
import json
import os
import secrets
import shutil
from pathlib import Path
from typing import Any

# 状态机：pending -> running -> packaging -> done
#                    \-> failed（任何阶段失败或进程中断）
ST_PENDING = "pending"
ST_RUNNING = "running"
ST_PACKAGING = "packaging"
ST_DONE = "done"
ST_FAILED = "failed"
TERMINAL = (ST_DONE, ST_FAILED)

_WORK_DIR = "extract"
_STATUS = "status.json"
_RESULT = "result.zip"


class DataLockError(Exception):
    pass


class JobStore:
    def __init__(self, data_dir: Path):
        self.data_dir = data_dir
        self.jobs_dir = data_dir / "jobs"
        self.jobs_dir.mkdir(parents=True, exist_ok=True)
        self._lock_fh: Any = None

    # ---- 进程级锁：防止两个实例同时清理/写同一批任务目录 ----
    def acquire_process_lock(self) -> None:
        lock_path = self.data_dir / "service.lock"
        lock_path.touch(exist_ok=True)
        fh = open(lock_path, "r+")
        try:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            fh.close()
            raise DataLockError(
                f"{self.data_dir} 已被另一个服务实例占用（{lock_path} 锁定中）"
            ) from exc
        self._lock_fh = fh

    def new_job_id(self) -> str:
        return secrets.token_hex(16)

    def job_dir(self, job_id: str) -> Path:
        if not all(c in "0123456789abcdef" for c in job_id) or len(job_id) != 32:
            raise ValueError("非法任务 id")
        return self.jobs_dir / job_id

    def work_dir(self, job_id: str) -> Path:
        return self.job_dir(job_id) / _WORK_DIR

    def result_path(self, job_id: str) -> Path:
        return self.job_dir(job_id) / _RESULT

    def create_job(self, job_id: str, filename: str) -> Path:
        jdir = self.job_dir(job_id)
        jdir.mkdir(parents=True, exist_ok=False)
        self.write_status(
            job_id,
            {
                "id": job_id,
                "status": ST_PENDING,
                "filename": filename,
                "error": None,
                "progress_pct": 0,
                "current_entry": None,
                "entries": 0,
                "total_entries": None,
                "bytes_written": 0,
                "result_size": None,
            },
        )
        return jdir

    def archive_path(self, job_id: str, suffix: str) -> Path:
        return self.job_dir(job_id) / f"archive{suffix}"

    def read_status(self, job_id: str) -> dict | None:
        path = self.job_dir(job_id) / _STATUS
        if not path.exists():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None

    def write_status(self, job_id: str, status: dict) -> None:
        path = self.job_dir(job_id) / _STATUS
        tmp = path.with_name(".status.json.tmp")
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(status, fh, ensure_ascii=False)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)  # 原子替换，读侧永远看到完整 json

    def list_jobs(self) -> list[dict]:
        out = []
        for jdir in sorted(self.jobs_dir.iterdir(), reverse=True):
            if not jdir.is_dir():
                continue
            st = self.read_status(jdir.name)
            if st:
                out.append(st)
        return out

    def remove_job(self, job_id: str) -> None:
        shutil.rmtree(self.job_dir(job_id), ignore_errors=True)

    def cleanup_workdir(self, job_id: str) -> None:
        shutil.rmtree(self.work_dir(job_id), ignore_errors=True)

    # ---- 崩溃恢复 ----
    def recover_on_startup(self) -> dict:
        """进程被杀后重启：没跑到 done 的任务全部判失败并清掉半成品。

        done 任务只认 result.zip 这个硬标记；标记齐全的一个文件都不动。
        """
        recovered = {"aborted": [], "kept_done": 0}
        for jdir in self.jobs_dir.iterdir():
            if not jdir.is_dir():
                continue
            job_id = jdir.name
            status = self.read_status(job_id)
            has_result = (jdir / _RESULT).is_file()

            if status and status.get("status") == ST_DONE and has_result:
                recovered["kept_done"] += 1
                continue

            # 连状态文件都没有的孤儿目录（极端情况下在建目录后、写状态前崩溃）
            if status is None:
                shutil.rmtree(jdir, ignore_errors=True)
                recovered["aborted"].append(job_id)
                continue

            # 半成品：失败任务 + 清理工作目录与原始包；状态留一份说明原因
            if status.get("status") not in TERMINAL:
                status["status"] = ST_FAILED
                status["error"] = "服务在解压过程中重启，任务被中止并清理"
                status["progress_pct"] = 0
                self.write_status(job_id, status)
            shutil.rmtree(jdir / _WORK_DIR, ignore_errors=True)
            for f in jdir.glob("archive.*"):
                f.unlink(missing_ok=True)
            (jdir / _RESULT).unlink(missing_ok=True)
            recovered["aborted"].append(job_id)
        return recovered
