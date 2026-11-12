"""服务配置，全部可以用环境变量覆盖。"""
import os
from dataclasses import dataclass
from pathlib import Path


def _env_int(key: str, default: int) -> int:
    try:
        return int(os.environ.get(key, str(default)))
    except ValueError:
        return default


@dataclass(frozen=True)
class Config:
    data_dir: Path = Path(
        os.environ.get("SAS_DATA_DIR", str(Path(__file__).resolve().parent / "data"))
    )
    # 上传压缩包本身的大小上限
    max_upload_mb: int = _env_int("SAS_MAX_UPLOAD_MB", 200)
    # 解压后所有文件累计大小上限（按实际写出的字节算）
    max_total_mb: int = _env_int("SAS_MAX_TOTAL_MB", 1024)
    # 解压后单个文件大小上限
    max_file_mb: int = _env_int("SAS_MAX_FILE_MB", 512)
    # 压缩包内条目数上限
    max_entries: int = _env_int("SAS_MAX_ENTRIES", 50_000)
    # 压缩比上限（解压后大小 / 压缩后大小），防 zip bomb
    max_ratio: int = _env_int("SAS_MAX_RATIO", 200)
    # 同时解压的任务数
    workers: int = _env_int("SAS_WORKERS", 2)
    host: str = os.environ.get("SAS_HOST", "127.0.0.1")
    port: int = _env_int("SAS_PORT", 8120)


CONFIG = Config()
