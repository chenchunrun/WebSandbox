# 恶意站点沙箱检测系统

基于 FastAPI + Celery + Playwright 的恶意站点检测服务，包含沙箱抓取、特征提取、规则模型初筛与灰区 LLM/VLM 分析。

## 已实现能力

- 沙箱抓取 (`sandbox-crawler`)
  - 原始响应头、重定向链、SSL基础信息
  - JS渲染后DOM快照
  - 桌面/移动截图
  - XHR/Fetch网络日志
  - 30秒超时、阻断下载类请求、阻断文档级POST提交
  - 可疑页面轻量CTA点击探测（`depth=deep` 或命中可疑关键词）
  - 支持每任务独立一次性容器执行抓取（`ISOLATION_MODE=docker_task`）
- 特征提取 (`feature-extractor`)
  - 域名年龄（WHOIS）与新域名判断
  - 自签名证书粗判
  - 品牌词与域名匹配度
  - 混淆JS、隐藏iframe、跨域表单提交
  - 风险语义关键词
- AI分析 (`ai-analyzer`)
  - Layer1规则/XGBoost初筛（支持挂载模型）
  - 灰区调用LLM/VLM（兼容OpenAI API）
  - 强制JSON输出
  - 输入清洗层（零宽字符去除、实体解码、控制字符过滤）
- API服务 (`api-server`)
  - `POST /analyze` 支持 `mode=sync|async`
  - `GET /analyze/{task_id}` 查询任务结果
  - `POST /analyze/batch` 支持 JSON 或 CSV(url列)
  - `POST /feedback` 人工误判标注回流
  - `POST /feedback/bulk` 批量标注导入
  - `GET /feedback/export` 与 `GET /feedback/export.csv` 导出训练样本
  - `GET /feedback/training-samples` 按条件筛选训练集
  - `GET /feedback/stats` 回流数据统计
  - `GET /model/status` 与 `POST /model/reload` 模型热更新
  - `GET /model/evaluate` 在线评估当前模型
  - `POST /model/promote` 与 `POST /model/rollback` 模型晋升/回滚
  - `GET /model/history` 模型治理审计日志
  - `GET /model/history/verify` 审计哈希链校验
  - `GET /policy` 查看当前判定与升级策略
  - `POST /policy/update` 与 `POST /policy/reset` 运行时策略热更新/回退（治理鉴权）
  - `GET /policy/history` 与 `POST /policy/rollback` 策略历史与按版本回滚

## 架构组件

- API: FastAPI
- Worker: Celery
- Queue/Backend: Redis
- Metadata: PostgreSQL
- Artifacts: MinIO
- Browser: Playwright Chromium

## 快速启动

```bash
cp .env.example .env
docker compose up --build
```

服务地址：
- API: http://localhost:8000
- MinIO Console: http://localhost:19001 (`minioadmin` / `minioadmin`)

端口可通过 `.env` 覆盖（默认值见 `.env.example`）：
- `API_HOST_PORT=8000`
- `REDIS_HOST_PORT=16379`
- `POSTGRES_HOST_PORT=15432`
- `MINIO_HOST_PORT=19000`
- `MINIO_CONSOLE_HOST_PORT=19001`

默认 `worker` 使用 `docker_task` 隔离模式：每个 URL 由独立短生命周期容器抓取，任务结束即销毁。
针对慢站点，默认启用“超时重试 + 本地回退”稳健策略（仅超时触发）：
- `CRAWL_TIMEOUT_QUICK_SECONDS=20`
- `CRAWL_TIMEOUT_STANDARD_SECONDS=30`
- `CRAWL_TIMEOUT_DEEP_SECONDS=45`
- `SANDBOX_TIMEOUT_RETRIES=1`
- `SANDBOX_RETRY_TIMEOUT_MULTIPLIER=1.5`
- `SANDBOX_FALLBACK_TO_LOCAL_ON_TIMEOUT=true`
- `SANDBOX_FALLBACK_TIMEOUT_SECONDS=45`
- `CELERY_TASK_TIME_LIMIT_SECONDS=300`

默认启用队列分级与基础资源预算（可按环境调整）：
- 队列分级：`QUEUE_QUICK` / `QUEUE_STANDARD` / `QUEUE_DEEP` / `QUEUE_RETRY`
- Worker 消费队列：`WORKER_QUEUES=quick,standard,deep,retry`
- DOM 字符预算：`MAX_DOM_CHARS=600000`
- XHR/Fetch 事件预算：`MAX_NETWORK_EVENTS=300`
- 重定向链预算：`MAX_REDIRECT_CHAIN=20`

默认启用策略引擎配置（可按环境调整）：
- 规则阈值：`RULE_MALICIOUS_THRESHOLD` / `RULE_BENIGN_THRESHOLD`
- 动作阈值：`ACTION_BLOCK_CONFIDENCE` / `ACTION_BENIGN_OBSERVE_CONFIDENCE`
- 交互升级策略：`DEEP_ESCALATION_ENABLED`、`DEEP_ESCALATION_KEYWORD_HIT_THRESHOLD`、`DEEP_ESCALATION_HIGH_RISK_XHR_THRESHOLD`
- 跨进程策略缓存TTL：`POLICY_CACHE_TTL_SECONDS`（默认2秒）

模型治理接口可选鉴权：
- 设置 `GOVERNANCE_API_KEY` 后，所有 `/model/*` 接口必须携带 `X-API-Key`。
- 建议同时携带 `X-Actor`（用户名/服务名），用于审计归因。

## 发布打包

建议发布形态：

- 源码版本标签：`vMAJOR.MINOR.PATCH`
- 应用镜像：`websandbox-api:<version>`、`websandbox-worker:<version>`
- Compose 交付包：`websandbox-<version>.tar.gz`

生成发布包：

```bash
scripts/package_release.sh v1.0.0
```

生成文件位于：

- `dist/websandbox-v1.0.0.tar.gz`
- `release/DEPLOYMENT.md`
- `release/RELEASE_CHECKLIST.md`

## 开源协议

本项目采用 Apache License 2.0 开源协议，详见仓库根目录 [LICENSE](./LICENSE)。

## 回归测试

发布前建议执行一次安全与功能回归：

```bash
scripts/run_regression_suite.sh
```

异步队列端到端回归（需要 Docker + worker）：

```bash
scripts/run_async_e2e_suite.sh
```

说明：

- 默认不自动构建镜像（`--no-build`），要求镜像已可用。
- 需要自动构建时可设置：`AUTO_BUILD=1 scripts/run_async_e2e_suite.sh`。

默认覆盖检查：

- 健康检查与治理鉴权
- 非法 URL 校验
- SSRF（目标 URL）拦截
- SSRF（callback_url）拦截
- 同步分析主流程
- 批量 JSON 接口解析（无 Celery 环境下验证 503 行为）
- 模型路径白名单约束
- 异步 E2E（使用 `scripts/run_async_e2e_suite.sh`）

运行指标接口：

- `GET /metrics`：返回进程内聚合指标（计数器与耗时聚合），可用于基础监控与告警接入。

## API示例

### 1) 同步分析

```bash
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com/login",
    "depth": "standard",
    "mode": "sync"
  }'
```

### 2) 异步分析

```bash
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com/login",
    "depth": "deep",
    "mode": "async"
  }'
```

查询结果：

```bash
curl http://localhost:8000/analyze/<task_id>
```

`verdict` 字段包含基础标签与风险标签体系：
- `label`: `phishing|malware|benign`
- `risk_type`: 如 `phishing|fake_brand|malware_delivery|suspicious_form|benign|unknown`
- `action`: `block|review|observe`
- `reason_codes`: 可枚举原因码数组（用于策略联动与统计）
- `evidence_score`: 0-100 证据强度分数

### 3) 批量分析(JSON)

```bash
curl -X POST http://localhost:8000/analyze/batch \
  -H "Content-Type: application/json" \
  -d '{
    "urls": ["https://a.com", "https://b.com/login"],
    "depth": "quick"
  }'
```

### 4) 批量分析(CSV)

CSV格式需要包含 `url` 列。

```bash
curl -X POST http://localhost:8000/analyze/batch \
  -F "file=@./targets.csv"
```

### 5) 误报反馈

```bash
curl -X POST http://localhost:8000/feedback \
  -H "Content-Type: application/json" \
  -d '{
    "task_id": "your-task-id",
    "human_label": "benign",
    "note": "人工复核为正常活动页",
    "reviewer": "sec-analyst-a"
  }'
```

### 6) 导出回流样本

JSON:

```bash
curl "http://localhost:8000/feedback/export?limit=1000&dedup_by_sample=true"
```

CSV字符串:

```bash
curl "http://localhost:8000/feedback/export.csv?limit=1000&dedup_by_sample=true"
```

导出结果新增样本治理字段：
- `sample_key`: 基于规范化 URL + 人工标签 + 关键特征的稳定样本键
- `label_source`: 当前固定为 `human_feedback`
- `can_use_for_training`: 是否可用于训练
- `dataset_version`: 导出快照指纹（用于复现训练集）

### 7) 批量反馈导入

```bash
curl -X POST http://localhost:8000/feedback/bulk \
  -H "Content-Type: application/json" \
  -d '{
    "items": [
      {"task_id": "task-1", "human_label": "benign", "reviewer": "sec-a"},
      {"task_id": "task-2", "human_label": "phishing", "note": "确认钓鱼页"}
    ]
  }'
```

### 8) 训练样本筛选导出

```bash
curl "http://localhost:8000/feedback/training-samples?limit=3000&only_false_positive=true&balanced=true&dedup_by_sample=true"
```

支持参数：
- `from_ts` / `to_ts`（ISO时间）
- `human_label=phishing|malware|benign`
- `only_false_positive=true|false`
- `balanced=true|false`（按三类标签均衡采样）
- `dedup_by_sample=true|false`

### 9) 回流统计

```bash
curl "http://localhost:8000/feedback/stats?from_ts=2026-04-01T00:00:00&to_ts=2026-04-15T23:59:59"
```

### 10) 模型热更新

查看当前模型状态：

```bash
curl -H "X-API-Key: change-me" -H "X-Actor: sec-admin" http://localhost:8000/model/status
```

强制重载模型：

```bash
curl -X POST -H "X-API-Key: change-me" -H "X-Actor: sec-admin" http://localhost:8000/model/reload
```

评估当前线上模型（基于反馈样本）：

```bash
curl -H "X-API-Key: change-me" -H "X-Actor: sec-admin" \
  "http://localhost:8000/model/evaluate?limit=2000&from_ts=2026-04-01T00:00:00"
```

评估后晋升 challenger（有门禁）：

```bash
curl -X POST http://localhost:8000/model/promote \
  -H "X-API-Key: change-me" \
  -H "X-Actor: sec-admin" \
  -H "Content-Type: application/json" \
  -d '{
    "challenger_path": "/tmp/xgb_model_v2.joblib",
    "min_delta_f1": 0.005,
    "limit": 2000,
    "from_ts": "2026-04-01T00:00:00",
    "dry_run": false
  }'
```

从备份回滚：

```bash
curl -X POST http://localhost:8000/model/rollback \
  -H "X-API-Key: change-me" \
  -H "X-Actor: sec-admin" \
  -H "Content-Type: application/json" \
  -d '{"backup_path": "/app/models/backups/xgb_model.20260415120000.joblib"}'
```

查看模型治理日志：

```bash
curl -H "X-API-Key: change-me" -H "X-Actor: auditor" "http://localhost:8000/model/history?limit=50"
curl -H "X-API-Key: change-me" -H "X-Actor: auditor" "http://localhost:8000/model/history?limit=20&event_type=promote"
curl -H "X-API-Key: change-me" -H "X-Actor: auditor" "http://localhost:8000/model/history?limit=20&event_status=error&from_ts=2026-04-15T00:00:00"
curl -H "X-API-Key: change-me" -H "X-Actor: auditor" "http://localhost:8000/model/history/export.csv?limit=1000&event_type=evaluate"
curl -H "X-API-Key: change-me" -H "X-Actor: auditor" "http://localhost:8000/model/history/verify?limit=5000"
```

审计完整性说明：
- `model_events` 使用 `prev_hash + event_hash` 链式签名，支持离线/在线校验篡改。
- 若是已存在数据库（非全新初始化），新增字段需要执行 schema migration（`ALTER TABLE model_events ADD COLUMN prev_hash ...`, `event_hash ...`）。

### 11) 运行时策略热更新

查看当前策略：

```bash
curl http://localhost:8000/policy
```

预览策略更新（不生效）：

```bash
curl -X POST http://localhost:8000/policy/update \
  -H "X-API-Key: change-me" \
  -H "X-Actor: sec-admin" \
  -H "Content-Type: application/json" \
  -d '{
    "rule": {"malicious_threshold": 0.85},
    "deep_escalation": {"keyword_hit_threshold": 3},
    "dry_run": true
  }'
```

应用策略更新（立即生效）：

```bash
curl -X POST http://localhost:8000/policy/update \
  -H "X-API-Key: change-me" \
  -H "X-Actor: sec-admin" \
  -H "Content-Type: application/json" \
  -d '{
    "rule": {"malicious_threshold": 0.85, "benign_threshold": 0.2},
    "action": {"block_confidence": 0.82}
  }'
```

回退到环境默认策略：

```bash
curl -X POST http://localhost:8000/policy/reset \
  -H "X-API-Key: change-me" \
  -H "X-Actor: sec-admin"
```

说明：
- 运行时策略覆盖持久化在 `policy_configs` 表，API 与 Worker 进程共享同一份策略。
- 变更会写入 `model_events` 审计链（`policy_update` / `policy_reset` / `policy_rollback`）。

查看策略变更历史：

```bash
curl -H "X-API-Key: change-me" -H "X-Actor: auditor" "http://localhost:8000/policy/history?limit=50"
```

按历史事件回滚策略（支持 dry-run）：

```bash
curl -X POST http://localhost:8000/policy/rollback \
  -H "X-API-Key: change-me" \
  -H "X-Actor: sec-admin" \
  -H "Content-Type: application/json" \
  -d '{"event_id":"<policy-event-id>","dry_run":true}'
```

```bash
curl -X POST http://localhost:8000/policy/rollback \
  -H "X-API-Key: change-me" \
  -H "X-Actor: sec-admin" \
  -H "Content-Type: application/json" \
  -d '{"event_id":"<policy-event-id>","dry_run":false}'
```

## XGBoost模型接入

将训练好的 `joblib` 模型挂载到容器路径 `/app/models/xgb_model.joblib`，模型输入特征顺序为：

1. is_new_domain
2. self_signed_cert
3. brand_domain_mismatch
4. js_obfuscation_hits
5. hidden_iframe_count
6. cross_domain_form_submit
7. keyword_hit_count
8. high_risk_xhr_count

## 误报反馈回流建议

当前版本已提供 `feedback_records` 回流表，并自动记录：

- 原任务URL和模型预测标签
- 人工标签和备注
- 是否误报（模型判恶意但人工判良性）
- 当时特征快照（`metadata.features`）

离线导出工具：

```bash
python scripts/export_feedback.py --output /tmp/feedback_export.csv
```

模型训练集构建：

```bash
python scripts/build_training_dataset.py \
  --output /tmp/training_dataset.csv \
  --from-ts 2026-04-01T00:00:00 \
  --balanced
```

XGBoost 训练（binary: benign vs malicious）：

```bash
python scripts/train_xgboost_model.py \
  --input /tmp/training_dataset.csv \
  --model-out /tmp/xgb_model.joblib \
  --metrics-out /tmp/xgb_metrics.json
```

模型离线验证：

```bash
python scripts/validate_xgboost_model.py \
  --model /tmp/xgb_model.joblib \
  --input /tmp/training_dataset.csv \
  --output /tmp/xgb_validation.json
```

Baseline/Challenger 对比：

```bash
python scripts/compare_xgboost_models.py \
  --baseline /tmp/xgb_model_v1.joblib \
  --challenger /tmp/xgb_model_v2.joblib \
  --input /tmp/training_dataset.csv \
  --output /tmp/xgb_compare.json
```

把训练模型用于在线初筛：

1. 将模型放到服务可读路径（如 `/app/models/xgb_model.joblib`）。
2. 启动时设置 `XGBOOST_MODEL_PATH=/app/models/xgb_model.joblib`。
3. 调用 `POST /model/reload` 立即重载 API 进程模型。
4. Worker 进程会在下一次推理时检测模型文件 `mtime` 自动重载。

## 安全与隔离说明

当前版本支持两种模式：

- `ISOLATION_MODE=local`：Worker容器内直接抓取（调试快）
- `ISOLATION_MODE=docker_task`：Worker通过 Docker Socket 拉起一次性抓取容器（推荐）

`docker_task` 模式默认限制：

- `--cpus=1.0`
- `--memory=1g`
- `--pids-limit=256`
- `--security-opt=no-new-privileges:true`
- `--cap-drop=ALL`

生产建议进一步升级为：

- Firecracker MicroVM 每URL独立实例
- 或 `runsc`(gVisor) + seccomp + cgroup 限额
- 出站网络策略按域/协议白名单
