# 工伤事故调查与纠正措施

记录工伤经过、伤害、现场和证人，维护调查、整改措施、安全管理员核验、关闭和复发退回流程。

## 模块结构

- `app.py`：参数解析、依赖组装和HTTP服务启动。
- `src/domain.py`：数据结构、错误、状态和基础校验。
- `src/rules.py`：状态机、角色矩阵、优先级、期限和关闭不变量。
- `src/repository.py`：SQLite建表、迁移、事务、版本控制、请求幂等和审计链。
- `src/service.py`：权限检查、用例编排、并发控制和审计。
- `src/http_api.py`：JSON路由和统一错误响应。
- `src/audit.py`：UTC时间和SHA-256审计事件。
- `static/index.html`：最小演示页。
- `tests/`：完整流程、规则和失败测试。

## 初始化与启动

```bash
python3 app.py --db ./data.db --port 8311
```

默认端口为`8311`，首次启动自动建库；旧数据库会自动补充核验、关闭、复发和措施关闭字段。使用`X-Actor`和`X-Role`请求头传递身份。

## 写入请求的一致性规则

所有创建、登记措施、关闭措施和状态流转请求都必须带`X-Request-ID`（也可在JSON body中提供`request_id`）。重试必须沿用同一个请求编号：

- 第一次请求成功后，相同编号和相同请求体返回首次响应，不会重复写入。
- 相同编号用于不同请求体会返回`409`。
- 业务写入和审计写入在同一个SQLite事务中提交；版本过期或审计写入失败时一起回滚。
- 失败且未提交的请求可沿用同一请求编号重试。

登记或关闭整改措施、状态流转都必须提交读取事故详情时得到的`expected_version`。版本过期返回`409`，调用方刷新后可用同一业务操作重新提交。

## 主要接口

- `GET /health`
- `GET /api/items`
- `POST /api/items`，需`X-Request-ID`
- `GET /api/items/{id}`
- `POST /api/items/{id}/records`，需`X-Request-ID`和`expected_version`
- `POST /api/items/{id}/records/{record_id}/close`，需`X-Request-ID`和`expected_version`
- `POST /api/items/{id}/transition`，需`X-Request-ID`和`expected_version`
- `GET /api/audit`

允许角色：reporter, investigator, safety_manager, viewer。严重度越高、伤害指数越大或未关闭措施越多，优先级越高；严重事故必须在4小时内启动调查。

## 关闭和复发联动

1. 存在未关闭整改措施时，不能提交安全管理员核验。
2. 安全管理员核验后，事故才能关闭。
3. 事故关闭后，普通记录只能以已关闭状态登记；凡登记`recurrence_risk=true`的复发风险措施（无论措施本身是否同时关闭），系统都在同一事务内：
   - 保留原整改措施和全部审计事件；
   - 清空原核验人和核验时间、关闭人和关闭时间；
   - 将事故退回到`verification`；
   - 在事故上保留`reopen_reason`，并写入`reopen_to_verification`审计事件。
4. 复发措施关闭后，安全管理员必须重新提交核验（从`verification`到`verification`），然后才能再次关闭。

## 测试

```bash
python3 -m unittest discover -s tests -v
```
