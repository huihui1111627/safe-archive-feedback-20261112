# 安全解压服务

接收外部发来的 zip / tar 压缩包，在沙箱式约束下解压，提供进度查看和结果下载。
后端 Flask，单文件前端，无数据库，状态靠任务目录里的 `status.json`。

## 跑起来

```bash
pip install -r requirements.txt
python3 app.py
# 打开 http://127.0.0.1:8120
```

跑测试（会自己起独立端口 8121 的实例，产物全在临时目录）：

```bash
python3 tests/e2e_test.py
```

## 配置（环境变量）

| 变量 | 默认值 | 含义 |
|---|---|---|
| `SAS_MAX_UPLOAD_MB` | 200 | 上传压缩包大小上限 |
| `SAS_MAX_TOTAL_MB` | 1024 | 解压后累计大小上限，**按实际写出字节算** |
| `SAS_MAX_FILE_MB` | 512 | 解压后单个文件上限 |
| `SAS_MAX_ENTRIES` | 50000 | 包内条目数上限 |
| `SAS_MAX_RATIO` | 200 | 压缩比上限，防 zip bomb |
| `SAS_WORKERS` | 2 | 并发解压线程数 |
| `SAS_PORT` | 8120 | 监听端口 |

## 安全设计

1. **不用库的一键解压**。`extractor.py` 逐条校验、流式写出，任何一条不过整包失败。
2. **路径越界**：`..` 穿越、绝对路径、Windows 盘符、反斜杠写法全部拒绝；
   最终目标再过一遍 `realpath`  containment 检查，防符号链接目录绕过。
3. **链接条目**：zip 的 symlink、tar 的 symlink/hardlink 一律拒绝；
   设备文件、FIFO 等非普通文件一律拒绝。写出的文件强制 `0644`，不带 setuid 位。
4. **大小按实际解压量**：包头声明大小只用来提前拒绝和压缩比检查，
   真正的限额在每个 chunk 写盘前从共享额度里扣，解压炸弹写到一半也会被截断。
5. **任务隔离**：每个任务独占 `data/jobs/<32位随机id>/`，id 服务端生成、格式严格校验，
   下载只认 `done` 状态且 `result.zip` 实际存在，否则 409/404。
6. **原子状态**：`status.json` 临时文件 + `os.replace`；结果包同样先写 `.tmp` 再改名，
   读到的永远是完整文件。
7. **崩溃恢复**：启动时扫任务目录——
   - `done` 且有 `result.zip` 的，一个文件不动；
   - 其他所有非终态/半成品任务标记 failed，清掉 `extract/`、原包和临时结果；
   - 连状态文件都没有的孤儿目录整个删掉。
8. **单实例锁**：`flock` 锁 `data/service.lock`，同一 data 目录不允许两个实例同时跑。

## 目录结构

```
data/jobs/<job_id>/
  archive.<ext>   原始包（任务失败或重启中止后删除）
  status.json     权威状态（原子写）
  extract/        解压工作目录（成功打包后、失败时都会清掉）
  result.zip      成功标记，存在即可下载
```

## 已验证的攻击场景（e2e_test.py，39 项断言）

zip-slip（`../`）、绝对路径、反斜杠穿越、zip symlink、tar symlink/hardlink、
字符设备、FIFO、高压缩比炸弹、超单文件限额、超上传限额、未完成任务下载、
运行中 `kill -9` 后重启恢复、双实例锁。测试在包外放了哨兵文件并做哈希终检，
确认全部攻击下包外文件零改动。
