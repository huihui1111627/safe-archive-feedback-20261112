"""端到端安全测试：构造恶意压缩包，对真实运行的服务打流量。

跑法：python3 tests/e2e_test.py
服务用独立端口和独立 data 目录，全部产物落在系统临时目录里。
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

PROJECT = Path(__file__).resolve().parent.parent
PORT = 8121
BASE = f"http://127.0.0.1:{PORT}"

PASS = 0
FAIL = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ✓ {name}")
    else:
        FAIL += 1
        print(f"  ✗ {name} {detail}")


# ---------- 恶意包构造 ----------

def make_benign_zip(path: Path) -> None:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("dir/hello.txt", "hello world\n")
        zf.writestr("dir/sub/data.bin", b"\x00\x01\x02\x03")


def make_benign_targz(path: Path) -> None:
    with tarfile.open(path, "w:gz") as tf:
        data = b"tar gz payload\n"
        info = tarfile.TarInfo("pkg/note.txt")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))


def make_zipslip_zip(path: Path) -> None:
    """条目用 ../ 穿越，目标直指包外哨兵文件。"""
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("../../sas-outside/sentinel.txt", "PWNED-ZIP\n")
        zf.writestr("normal.txt", "ok")


def make_abs_path_zip(path: Path) -> None:
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("/tmp/sas-outside/abs.txt", "PWNED-ABS\n")


def make_backslash_zip(path: Path) -> None:
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("..\\..\\sas-outside\\bs.txt", "PWNED-BS\n")


def make_symlink_zip(path: Path) -> None:
    info = zipfile.ZipInfo("link-to-outside")
    info.create_system = 3  # Unix
    info.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr(info, "../../sas-outside/sentinel.txt")


def make_tar_with(path: Path, mode: str) -> None:
    with tarfile.open(path, mode) as tf:
        good = b"safe\n"
        ti = tarfile.TarInfo("ok.txt")
        ti.size = len(good)
        tf.addfile(ti, io.BytesIO(good))

        if mode.startswith("w"):  # 未压缩 tar 才能放这些特殊条目
            if path.name.endswith("symlink.tar"):
                ti = tarfile.TarInfo("evil-link")
                ti.type = tarfile.SYMTYPE
                ti.linkname = "../../sas-outside/sentinel.txt"
                tf.addfile(ti)
            elif path.name.endswith("hardlink.tar"):
                ti = tarfile.TarInfo("evil-hard")
                ti.type = tarfile.LNKTYPE
                ti.linkname = "../../sas-outside/sentinel.txt"
                tf.addfile(ti)
            elif path.name.endswith("device.tar"):
                ti = tarfile.TarInfo("evil-char-dev")
                ti.type = tarfile.CHRTYPE
                ti.devmajor = 1
                ti.devminor = 3
                tf.addfile(ti)
            elif path.name.endswith("fifo.tar"):
                ti = tarfile.TarInfo("evil-fifo")
                ti.type = tarfile.FIFOTYPE
                tf.addfile(ti)


def make_bomb_zip(path: Path, size_mb: int = 5) -> None:
    """高压缩比炸弹：全零数据，压缩后极小、解压后很大。"""
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("bomb.bin", b"\x00" * size_mb * 1024 * 1024)


def make_bigfile_zip(path: Path, size_mb: int = 2) -> None:
    """高压缩的大文件：压缩后很小能过上传关，但解压后超单文件限额。"""
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("big.bin", b"\x00" * size_mb * 1024 * 1024)


def make_oversize_upload_zip(path: Path, size_mb: int = 3) -> None:
    """不可压缩、超过上传限额的包，直接被 413 挡住。"""
    with zipfile.ZipFile(path, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("big.bin", os.urandom(size_mb * 1024 * 1024))


def make_targz_bomb(path: Path, size_mb: int = 5) -> None:
    """tar.gz 炸弹：gzip 后极小，解压出的 tar 里是大文件，专门打 tar 侧的膨胀检查。"""
    blob = b"\x00" * size_mb * 1024 * 1024
    with tarfile.open(path, "w:gz") as tf:
        info = tarfile.TarInfo("boom.bin")
        info.size = len(blob)
        tf.addfile(info, io.BytesIO(blob))


def make_duplicate_zip(path: Path) -> None:
    """同一相对路径写两次，第二次应当触发冲突拒绝，不能静默覆盖。"""
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("same.txt", "first\n")
        zf.writestr("same.txt", "second\n")


def make_pax_longname_tar(path: Path) -> None:
    """PAX 长名条目，名字藏在扩展头里，后缀拼上穿越路径。"""
    long_prefix = "a" * 120
    name = long_prefix + "/../../sas-outside/pax.txt"
    data = b"pax-pwn\n"
    with tarfile.open(path, "w", format=tarfile.PAX_FORMAT) as tf:
        info = tarfile.TarInfo(name)
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))


def make_gzip_not_tar(path: Path) -> None:
    """内容是 gzip 但里面不是 tar 归档，应该得到明确的格式错误而不是 500。"""
    import gzip
    with gzip.open(path, "wb") as fh:
        fh.write(b"this is just gzipped plain text, not a tar\n")


# ---------- HTTP 辅助 ----------

def wait_port(timeout: float = 10.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", PORT), 0.5):
                return
        except OSError:
            time.sleep(0.2)
    raise RuntimeError("服务没在规定时间内启动")


def upload(archive: Path):
    boundary = "----sastest" + hashlib.md5(str(archive).encode()).hexdigest()
    body = b"".join([
        f"--{boundary}\r\n".encode(),
        f'Content-Disposition: form-data; name="archive"; filename="{archive.name}"\r\n'.encode(),
        b"Content-Type: application/octet-stream\r\n\r\n",
        archive.read_bytes(),
        f"\r\n--{boundary}--\r\n".encode(),
    ])
    req = urllib.request.Request(
        BASE + "/api/jobs", data=body, method="POST",
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read())
        except Exception:
            return e.code, {}


def get_json(path: str):
    try:
        with urllib.request.urlopen(BASE + path, timeout=10) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def wait_job(job_id: str, timeout: float = 30.0) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        _, st = get_json(f"/api/jobs/{job_id}")
        if st.get("status") in ("done", "failed"):
            return st
        time.sleep(0.3)
    raise TimeoutError(job_id)


def start_server(data_dir: Path, env_extra: dict | None = None):
    env = os.environ.copy()
    env.update({
        "SAS_DATA_DIR": str(data_dir),
        "SAS_PORT": str(PORT),
        "SAS_MAX_UPLOAD_MB": "2",
        "SAS_MAX_TOTAL_MB": "2",
        "SAS_MAX_FILE_MB": "1",
        "SAS_MAX_RATIO": "100",
        "SAS_WORKERS": "1",
    })
    if env_extra:
        env.update(env_extra)
    data_dir.mkdir(parents=True, exist_ok=True)
    log = open(data_dir / "server.log", "wb")
    proc = subprocess.Popen(
        [sys.executable, "-I", str(PROJECT / "app.py")],
        cwd=PROJECT, env=env, stdout=log, stderr=subprocess.STDOUT,
    )
    wait_port()
    return proc


def stop_server(proc) -> None:
    proc.send_signal(signal.SIGTERM)
    proc.wait(timeout=10)


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="sas-e2e-"))
    data_dir = tmp / "data"
    fix_dir = tmp / "fixtures"
    outside = tmp / "sas-outside"
    outside.mkdir(parents=True)
    sentinel = outside / "sentinel.txt"
    sentinel.write_text("ORIGINAL-CONTENT\n")
    sentinel_hash = hashlib.sha256(sentinel.read_bytes()).hexdigest()

    fix_dir.mkdir()
    fixtures = {
        "benign.zip": make_benign_zip,
        "benign.tar.gz": make_benign_targz,
        "zipslip.zip": make_zipslip_zip,
        "abspath.zip": make_abs_path_zip,
        "backslash.zip": make_backslash_zip,
        "symlink.zip": make_symlink_zip,
    }
    for name, fn in fixtures.items():
        fn(fix_dir / name)
    for name in ("symlink.tar", "hardlink.tar", "device.tar", "fifo.tar"):
        make_tar_with(fix_dir / name, "w")
    make_bomb_zip(fix_dir / "bomb.zip")
    make_bigfile_zip(fix_dir / "bigfile.zip")
    make_oversize_upload_zip(fix_dir / "oversize.zip")
    make_targz_bomb(fix_dir / "bomb.tar.gz")
    make_duplicate_zip(fix_dir / "duplicate.zip")
    make_pax_longname_tar(fix_dir / "paxlong.tar")
    make_gzip_not_tar(fix_dir / "plain.gz")

    proc = start_server(data_dir)
    try:
        print("== 1. 正常包全流程 ==")
        code, resp = upload(fix_dir / "benign.zip")
        check("上传返回 201", code == 201, str(code))
        job_id = resp["id"]
        st = wait_job(job_id)
        check("正常 zip 任务完成", st["status"] == "done", str(st.get("error")))
        check("实际解压字节按内容统计", st["bytes_written"] == len("hello world\n") + 4)

        with urllib.request.urlopen(BASE + f"/api/jobs/{job_id}/download") as r:
            check("成功任务可下载", r.status == 200)
            result_zip = tmp / "result.zip"
            result_zip.write_bytes(r.read())
        with zipfile.ZipFile(result_zip) as zf:
            names = set(zf.namelist())
            check("结果包内容正确", names == {"dir/hello.txt", "dir/sub/data.bin"}, str(names))
            check("文件内容一致", zf.read("dir/hello.txt") == b"hello world\n")
        check("成功任务的工作目录已清理", not (data_dir / "jobs" / job_id / "extract").exists())

        code, resp = upload(fix_dir / "benign.tar.gz")
        st = wait_job(resp["id"])
        check("正常 tar.gz 任务完成", st["status"] == "done", str(st.get("error")))

        print("== 2. 路径越界类攻击 ==")
        for name in ("zipslip.zip", "abspath.zip", "backslash.zip", "paxlong.tar"):
            code, resp = upload(fix_dir / name)
            st = wait_job(resp["id"])
            check(f"{name} 被拒绝", st["status"] == "failed" and "路径" in (st["error"] or ""),
                  str(st.get("error")))
            jdir = data_dir / "jobs" / resp["id"]
            check(f"{name} 失败后无半成品/原包残留",
                  not (jdir / "extract").exists() and not list(jdir.glob("archive.*")))

        print("== 2b. 重复条目与伪装格式 ==")
        code, resp = upload(fix_dir / "duplicate.zip")
        st = wait_job(resp["id"])
        check("重复路径条目被拒绝", st["status"] == "failed" and "冲突" in (st["error"] or ""),
              str(st.get("error")))
        code, resp = upload(fix_dir / "plain.gz")
        st = wait_job(resp["id"])
        check("gzip 非 tar 报明确格式错误", st["status"] == "failed" and "tar" in (st["error"] or ""),
              str(st.get("error")))

        print("== 3. 链接与特殊文件 ==")
        for name in ("symlink.zip", "symlink.tar", "hardlink.tar", "device.tar", "fifo.tar"):
            code, resp = upload(fix_dir / name)
            st = wait_job(resp["id"])
            check(f"{name} 被拒绝", st["status"] == "failed", str(st.get("error")))

        print("== 4. 解压炸弹与大小限制（按实际解压量）=")
        code, resp = upload(fix_dir / "bomb.zip")
        st = wait_job(resp["id"])
        check("高压缩比炸弹被拒绝", st["status"] == "failed", str(st.get("error")))
        jdir = data_dir / "jobs" / resp["id"]
        check("炸弹失败后解压目录被清掉", not (jdir / "extract").exists())

        code, resp = upload(fix_dir / "bomb.tar.gz")
        st = wait_job(resp["id"])
        check("tar.gz 高膨胀炸弹被拒绝", st["status"] == "failed", str(st.get("error")))
        check("tar.gz 炸弹拒绝原因是炸弹/超限",
              ("炸弹" in (st["error"] or "")) or ("超限" in (st["error"] or "")),
              str(st.get("error")))

        code, resp = upload(fix_dir / "bigfile.zip")
        st = wait_job(resp["id"])
        check("超单文件限额被拒绝", st["status"] == "failed" and "单文件" in (st["error"] or ""),
              str(st.get("error")))

        jobs_before = {p.name for p in (data_dir / "jobs").iterdir() if p.is_dir()}
        code, resp = upload(fix_dir / "oversize.zip")
        check("超上传限额返回 413", code == 413, str(code))
        jobs_after = {p.name for p in (data_dir / "jobs").iterdir() if p.is_dir()}
        check("413 后不留孤儿任务目录", jobs_before == jobs_after,
              f"新增残留: {jobs_after - jobs_before}")

        print("== 5. 下载权限与任务隔离 ==")
        code, _ = get_json(f"/api/jobs/{resp.get('id', 'x' * 32)}/download")
        check("未成功任务下载被拒（409/404）", code in (409, 404), str(code))
        code, _ = get_json("/api/jobs/" + "a" * 32 + "/download")
        check("不存在任务下载返回 404", code == 404, str(code))
        job_dirs = [p for p in (data_dir / "jobs").iterdir() if p.is_dir()]
        check("每个任务独立目录、id 互不重叠", len({p.name for p in job_dirs}) == len(job_dirs))

        print("== 6. 运行中强杀进程的恢复 ==")
        # 这个阶段需要更大的限额：停掉小限额实例，用同 data 目录重启
        stop_server(proc)
        proc = start_server(data_dir, {
            "SAS_MAX_UPLOAD_MB": "16",
            "SAS_MAX_TOTAL_MB": "16",
            "SAS_MAX_FILE_MB": "16",
        })
        # 造一个解压要花点时间的包：1500 个 8KB 随机文件，STORED 不压缩
        slow = fix_dir / "slow.zip"
        with zipfile.ZipFile(slow, "w", zipfile.ZIP_STORED) as zf:
            for i in range(1500):
                zf.writestr(f"f/{i:05d}.dat", os.urandom(8192))
        code, resp = upload(slow)
        kill_id = resp["id"]
        # 等到确实进入 running 且 extract 里有半成品再杀
        killed = False
        for _ in range(100):
            _, s = get_json(f"/api/jobs/{kill_id}")
            extract = data_dir / "jobs" / kill_id / "extract"
            if s.get("status") == "running" and extract.exists() and any(extract.rglob("*")):
                proc.kill()
                proc.wait()
                killed = True
                break
            time.sleep(0.05)
        check("捕捉到运行态并强杀", killed)
        leftover = list((data_dir / "jobs" / kill_id / "extract").rglob("*"))
        check("强杀时确实留了半成品", len(leftover) > 0)

        proc = start_server(data_dir)
        _, st = get_json(f"/api/jobs/{kill_id}")
        check("重启后半成品任务标记 failed", st["status"] == "failed")
        check("重启后半成品被清掉", not (data_dir / "jobs" / kill_id / "extract").exists())
        check("重启后原包被清掉", not list((data_dir / "jobs" / kill_id).glob("archive.*")))
        _, kept = get_json(f"/api/jobs/{job_id}")
        check("已完成任务不受重启影响", kept["status"] == "done")
        check("已完成任务结果仍可下载",
              (data_dir / "jobs" / job_id / "result.zip").is_file())

        print("== 7. 进程锁 ==")
        env = os.environ.copy()
        env.update({"SAS_DATA_DIR": str(data_dir), "SAS_PORT": "8122"})
        p2 = subprocess.Popen(
            [sys.executable, "-I", str(PROJECT / "app.py")],
            cwd=PROJECT, env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        rc = p2.wait(timeout=10)
        check("同 data 目录的第二个实例拒绝启动", rc != 0)

    finally:
        if proc.poll() is None:
            stop_server(proc)

    print("== 8. 包外哨兵文件终检 ==")
    now_hash = hashlib.sha256(sentinel.read_bytes()).hexdigest()
    check("哨兵文件内容从头到尾没被改过", now_hash == sentinel_hash)
    stray = [p for p in outside.rglob("*") if p.name != "sentinel.txt"]
    check("包外目录没有出现任何新文件", not stray, str(stray))

    # 确定性恢复：手造一个 running 半成品 + 一个完整 done，再重启
    print("== 9. 确定性恢复演练 ==")
    fake_id = "b" * 32
    jdir = data_dir / "jobs" / fake_id
    (jdir / "extract" / "d").mkdir(parents=True)
    (jdir / "extract" / "d" / "half.dat").write_bytes(b"x" * 100)
    (jdir / "archive.zip").write_bytes(b"PK")
    (jdir / "status.json").write_text(json.dumps({
        "id": fake_id, "status": "running", "filename": "x.zip",
        "error": None, "progress_pct": 42,
    }))
    proc = start_server(data_dir)
    try:
        _, st = get_json(f"/api/jobs/{fake_id}")
        check("伪造的 running 任务被恢复为 failed", st["status"] == "failed")
        check("伪造任务的半成品被清", not (jdir / "extract").exists())
        check("伪造任务的原包被清", not (jdir / "archive.zip").exists())
    finally:
        stop_server(proc)

    shutil.rmtree(tmp, ignore_errors=True)
    print(f"\n结果：{PASS} 通过，{FAIL} 失败")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
