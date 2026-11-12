"""安全解压服务 HTTP 入口。"""
from __future__ import annotations

import logging
import shutil
import threading
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from flask import (
    Flask,
    abort,
    jsonify,
    render_template,
    request,
    send_file,
)

from config import CONFIG
from extractor import UnsafeArchiveError, extract_archive
from jobs import (
    ST_DONE,
    ST_FAILED,
    ST_PACKAGING,
    ST_PENDING,
    ST_RUNNING,
    DataLockError,
    JobStore,
)

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s"
)
log = logging.getLogger("sas")

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = CONFIG.max_upload_mb * 1024 * 1024

store = JobStore(CONFIG.data_dir)

# 内存态只用于高频进度刷新；磁盘 status.json 才是权威状态
_memory: dict[str, dict] = {}
_mem_lock = threading.Lock()
_pool = ThreadPoolExecutor(max_workers=CONFIG.workers, thread_name_prefix="extract")

_ALLOWED_SUFFIX = {
    ".zip",
    ".tar",
    ".gz",
    ".tgz",
    ".bz2",
    ".xz",
    ".tar.gz",
    ".tar.xz",
    ".tar.bz2",
}


def _mem_get(job_id: str) -> dict | None:
    with _mem_lock:
        return _memory.get(job_id)


def _mem_put(job_id: str, status: dict) -> None:
    with _mem_lock:
        _memory[job_id] = status


def _mem_drop(job_id: str) -> None:
    with _mem_lock:
        _memory.pop(job_id, None)


def get_status(job_id: str) -> dict | None:
    return _mem_get(job_id) or store.read_status(job_id)


def _sanitize_suffix(filename: str) -> str:
    name = Path(filename).name
    for suf in sorted(_ALLOWED_SUFFIX, key=len, reverse=True):
        if name.lower().endswith(suf):
            return suf
    return ".bin"


def _package_result(job_id: str, status: dict) -> None:
    """把解压目录重新打成 result.zip，先写临时文件再原子改名。"""
    work = store.work_dir(job_id)
    tmp = store.job_dir(job_id) / "result.zip.tmp"
    final = store.result_path(job_id)
    status["status"] = ST_PACKAGING
    status["progress_pct"] = 99
    _mem_put(job_id, status)
    store.write_status(job_id, status)

    with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        for path in sorted(work.rglob("*")):
            if path.is_file():  # 解压时已拒绝链接，这里只会遇到普通文件/目录
                zf.write(path, path.relative_to(work))

    size = tmp.stat().st_size
    tmp.rename(final)

    # 结果已落盘，工作目录不再需要
    shutil.rmtree(work, ignore_errors=True)
    status["status"] = ST_DONE
    status["progress_pct"] = 100
    status["result_size"] = size
    store.write_status(job_id, status)
    _mem_put(job_id, status)
    _mem_drop(job_id)


def _run_job(job_id: str) -> None:
    status = store.read_status(job_id)
    if status is None:
        return
    try:
        archive = next(store.job_dir(job_id).glob("archive.*"))
        status["status"] = ST_RUNNING
        _mem_put(job_id, status)
        store.write_status(job_id, status)

        last_disk_write = 0.0

        def progress(index: int, total: int, entry_name: str) -> None:
            pct = int(index * 100 / total) if total else 0
            status["current_entry"] = entry_name
            status["entries"] = index
            status["total_entries"] = total
            status["progress_pct"] = pct
            _mem_put(job_id, status)
            nonlocal last_disk_write
            now = time.monotonic()
            # 磁盘状态限频写，避免条目多时刷盘过多；内存态仍然每次更新
            if now - last_disk_write > 0.25:
                store.write_status(job_id, status)
                last_disk_write = now

        result = extract_archive(
            archive, store.work_dir(job_id), CONFIG, progress
        )
        status["bytes_written"] = result.bytes_written
        status["kind"] = result.kind
        store.write_status(job_id, status)
        _package_result(job_id, status)
        log.info("job %s done: %s, %d bytes", job_id, result.kind, result.bytes_written)

    except UnsafeArchiveError as exc:
        _fail_job(job_id, f"安全检查未通过：{exc}")
    except Exception:
        log.exception("job %s failed unexpectedly", job_id)
        _fail_job(job_id, "服务内部错误，任务已中止并清理")


def _fail_job(job_id: str, message: str) -> None:
    status = store.read_status(job_id) or {"id": job_id}
    status["status"] = ST_FAILED
    status["error"] = message
    status["progress_pct"] = 0
    store.write_status(job_id, status)
    _mem_put(job_id, status)
    _mem_drop(job_id)
    # 失败：清掉解压半成品和原始包，杜绝残留被其他途径读到
    store.cleanup_workdir(job_id)
    for f in store.job_dir(job_id).glob("archive.*"):
        f.unlink(missing_ok=True)
    (store.job_dir(job_id) / "result.zip.tmp").unlink(missing_ok=True)
    log.warning("job %s failed: %s", job_id, message)


# ---------------- 路由 ----------------

@app.get("/")
def index():
    return render_template(
        "index.html",
        max_upload_mb=CONFIG.max_upload_mb,
        max_total_mb=CONFIG.max_total_mb,
    )


@app.post("/api/jobs")
def create_job():
    upload = request.files.get("archive")
    if upload is None or not upload.filename:
        return jsonify({"error": "请选择要上传的压缩包"}), 400

    job_id = store.new_job_id()
    jdir = store.create_job(job_id, Path(upload.filename).name)
    archive = store.archive_path(job_id, _sanitize_suffix(upload.filename))
    # 先存为临时文件，完整落盘后再改名，崩溃不会留下半个 archive
    tmp = jdir / "archive.uploading"
    upload.save(tmp)
    tmp.rename(archive)

    _pool.submit(_run_job, job_id)
    log.info("job %s created for %s", job_id, upload.filename)
    return jsonify({"id": job_id}), 201


@app.get("/api/jobs")
def list_jobs():
    return jsonify(store.list_jobs())


@app.get("/api/jobs/<job_id>")
def job_detail(job_id: str):
    try:
        status = get_status(job_id)
    except ValueError:
        abort(404)
    if status is None:
        abort(404)
    return jsonify(status)


@app.get("/api/jobs/<job_id>/download")
def download(job_id: str):
    try:
        status = get_status(job_id)
    except ValueError:
        abort(404)
    if status is None:
        abort(404)
    # 只有 done 且 result.zip 实际存在才开放下载
    if status.get("status") != ST_DONE or not store.result_path(job_id).is_file():
        abort(409, description="任务尚未成功完成，结果不可下载")
    stem = Path(status.get("filename", "archive")).stem or "archive"
    return send_file(
        store.result_path(job_id),
        as_attachment=True,
        download_name=f"{stem}_extracted.zip",
    )


@app.errorhandler(413)
def too_large(_err):
    return jsonify(
        {"error": f"压缩包超过上传上限 {CONFIG.max_upload_mb} MB"}
    ), 413


@app.errorhandler(404)
def not_found(_err):
    return jsonify({"error": "任务不存在"}), 404


@app.errorhandler(409)
def conflict(err):
    return jsonify({"error": err.description}), 409


def main() -> None:
    try:
        store.acquire_process_lock()
    except DataLockError as exc:
        raise SystemExit(str(exc)) from exc
    recovered = store.recover_on_startup()
    log.info(
        "启动恢复：保留已完成任务 %d 个，中止并清理半成品任务 %d 个",
        recovered["kept_done"],
        len(recovered["aborted"]),
    )
    app.run(host=CONFIG.host, port=CONFIG.port, threaded=True)


if __name__ == "__main__":
    main()
