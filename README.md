# CIDR Policy Normalizer

基于 **Python + FastAPI + 标准库 `ipaddress`** 的 CIDR 策略规范化 API。

接收 `allow` 与 `deny` 两个 CIDR 列表，分别对 **IPv4 / IPv6** 计算集合差
**allow − deny**，返回与原策略**等价、互不重叠且数量最少**的 CIDR 集合。
另提供地址判定（`/evaluate`）、策略对比（`/compare`）、规则影响审计
（`/audit-rules`）、策略最小化（`/minimize-policy`）、子网分配
（`/allocate`）、地址/网段密钥脱敏（`/anonymize`）、同一 `/24` 内
IPv4 网段的反向 DNS 委派计划（`/reverse-delegations`）、单个 scope 内
拟发布路由的 RPKI ROA 覆盖状态分区（`/roa-coverage`）、无向 AS 关系的
无谷路径修复（`/as-relationship-repair`）以及 RFC 6052 网络特定前缀的
NAT64 IPv4/IPv6 地址编解码（`/nat64-codec`）接口，以及在单个 scope 内按
十进制序号定位空闲 IP（`/free-addresses`）接口。

- deny 前缀切穿 allow 网段时，按二叉前缀树**递归对半拆分**直到边界对齐；
- 仅当两个网段构成**完整相邻的兄弟前缀**（同一父网的左右两半）时才合并，
  借助 `ipaddress.collapse_addresses` 实现，保证最小化且不会跨边界聚合；
- 输出按 **地址族（IPv4 → IPv6）→ 网络地址 → 前缀长度** 稳定排序；
- 统计 allow / deny 的输入数量、去重后数量（按族拆分）与最终输出数量；
- `/audit-rules` 在单个 scope 内基于 **CIDR 分区**（不枚举地址）逐条判断
  规则为 `effective` / `shadowed` / `out_of_scope`，给出最小 witness IP 与
  使其无法获胜的规则索引集合，兼容 IPv4/IPv6；
- `/minimize-policy` 在单个 scope 内基于 **CIDR 分区 + 精确分支限界搜索**
  （不枚举地址、不逐条贪心删除）求出与原策略判定完全一致的**最少规则子集**，
  多组最少解按保留规则的 `(side, index)` 序列字典序取唯一结果；
- `/allocate` 在单个 scope 内为多条申请分配互不重叠、避开占用网段的子网，
  按申请顺序取**网络地址序列字典序最小**的完整可行方案（必要时回溯）；
- `/reverse-delegations` 为**同一 `/24`** 内的多个 IPv4 网段（严格
  CIDR，仅 `/24`～`/32`）生成反向 DNS 委派计划：`/24` 直接委派
  `in-addr.arpa` 区域（NS），`/25`～`/32` 按 **RFC 2317** 以
  「`<网络地址末段>/<前缀>`」范围标签委派子区（NS），并由父区为覆盖的
  每个地址发布指向子区内 PTR 名称的 CNAME；网段相交或跨 `/24` 整批拒绝；
- `/roa-coverage` 在单个 scope 内对**拟发布的固定前缀长度**的每一条对齐候选
  路由，按 ROA 前缀包含关系给出 RPKI **`valid` / `invalid` / `unknown`**
  状态，并输出**按网络地址排序、互不重叠的最小 CIDR 状态分区**（分区可短于
  拟发布前缀长度）；全程只沿 ROA 边界做前缀树切分，**不逐个枚举候选子网**，
  可直接处理 `::/0`、候选为 `/128` 的超大 IPv6 范围；
- `/as-relationship-repair` 在至多 9 条无向 AS 关系（客户-提供商或对等）
  与至多 20 条起源到接收 AS 路径之间，允许把一条关系改成另一种客户-提供商
  方向或对等关系，以**改动关系条数最少**为目标令全部路径同时满足
  「上行\*、至多一次对等、下行\*」的**无谷（valley-free）规则**；同一关系
  在各路径中**共用同一个修正结果**，同分按 AS 对排序后的**新关系序列
  字典序**取唯一方案，无可行方案返回 **HTTP 409**；
- `/nat64-codec` 按 **RFC 6052** 的网络特定前缀（Network-Specific Prefix，
  仅允许 **`/32`、`/40`、`/48`、`/56`、`/64`、`/96`**）把 IPv4 地址
  嵌入 IPv6（编码），并把映射后的 IPv6 地址还原为 IPv4（解码）；IPv4
  位跨第 64 位边界安放、**u 八位及剩余后缀全部置零**，`/96` 时 IPv4
  直接接在前缀之后；解码逐个校验前缀、u 八位与后缀均为规范值，任一非法
  地址或非规范映射**整批返回 422**；
- `/free-addresses` 在**单个严格 CIDR scope** 内统计空闲地址总数，并把若干
  **从 0 开始的十进制序号**映射为按地址数值升序排列的空闲地址；占用网段可
  **互相重叠、超出 scope**（先求并集、再裁剪到 scope 后扣除），**所有地址
  位都计数**（含网络/广播地址），全程只在网段与数量上运算、**不逐个枚举
  地址**，可直接处理 IPv6 `::/0`；序号越界（达到空闲总数）、CIDR 非法或
  地址族不一致**整批返回 422**，空序号列表仍返回总数；
- 非法 CIDR（格式错误、越界前缀、主机位非零）统一返回 **HTTP 422**。

## 一条命令启动

依赖在镜像构建时安装完成，容器启动即提供服务：

```bash
docker compose up -d --build
```

服务监听宿主机 **8000** 端口（容器内固定 8000）。

健康检查：

```bash
curl http://localhost:8000/health
# {"status":"ok"}
```

交互式文档：<http://localhost:8000/docs>

## 配置

无需任何必填配置。唯一可选项是宿主机映射端口（容器内始终为 8000）：

```bash
HOST_PORT=9000 docker compose up -d --build   # 宿主机改用 9000
```

默认端口：**8000**（见 `docker-compose.yml` 的 `${HOST_PORT:-8000}:8000`）。

## API

### `POST /normalize`

请求体：

| 字段   | 类型       | 说明                                   |
| ------ | ---------- | -------------------------------------- |
| `allow` | `string[]` | 允许列表，IPv4/IPv6 可混填，可省略（默认 `[]`） |
| `deny`  | `string[]` | 拒绝列表，规则同上                     |

CIDR 规则：

- 标准 CIDR：`10.0.0.0/24`、`2001:db8::/32`；
- 裸地址按主机前缀处理：`10.0.0.1` ≡ `10.0.0.1/32`，`::1` ≡ `::1/128`；
- 主机位非零（如 `10.0.0.1/24`）视为非法，返回 422。

示例：

```bash
curl -s -X POST http://localhost:8000/normalize \
  -H 'Content-Type: application/json' \
  -d '{
        "allow": ["10.0.0.0/24", "10.0.0.0/24", "2001:db8::/32"],
        "deny":  ["10.0.0.128/25", "2001:db8:1::/48"]
      }'
```

响应：

```json
{
  "ipv4": ["10.0.0.0/25"],
  "ipv6": ["2001:db8::/48", "2001:db8:2::/47", "... 共 16 段 ..."],
  "stats": {
    "allow": {"input": 3, "unique": 2, "duplicates_removed": 1, "ipv4": 1, "ipv6": 1},
    "deny":  {"input": 2, "unique": 2, "duplicates_removed": 0, "ipv4": 1, "ipv6": 1},
    "output": {"ipv4": 1, "ipv6": 16, "total": 17}
  }
}
```

字段说明：

- `ipv4` / `ipv6`：allow − deny 的最小 CIDR 列表，按网络地址、前缀长度排序；
- `stats.allow` / `stats.deny`：
  - `input`：请求中的原始条目数；
  - `unique`：去重后的网络数；
  - `duplicates_removed`：被去掉的重复条目数；
  - `ipv4` / `ipv6`：去重后各地址族的网络数；
- `stats.output`：最终输出的 IPv4 / IPv6 及总网段数。

非法输入返回 422：

```bash
curl -i -X POST http://localhost:8000/normalize \
  -H 'Content-Type: application/json' \
  -d '{"allow": ["10.0.0.1/24"], "deny": []}'
# HTTP/1.1 422 Unprocessable Entity
# {"detail":[{"type":"value_error","loc":["body","allow"],
#   "msg":"Value error, 10.0.0.1/24 has host bits set", ...}]}
```

### `POST /evaluate`

接收与 `/normalize` 相同的 `allow` / `deny` CIDR 列表，外加一个 `addresses`
裸地址列表，对每个地址做**最长前缀匹配**，并按 `addresses` 的原顺序逐条返回
判定结果。

请求体：

| 字段        | 类型       | 说明                                   |
| ----------- | ---------- | -------------------------------------- |
| `allow`     | `string[]` | 允许列表，IPv4/IPv6 可混填，可省略（默认 `[]`） |
| `deny`      | `string[]` | 拒绝列表，规则同上                     |
| `addresses` | `string[]` | 待判定的**裸 IP 地址**（不接受 CIDR 记法），顺序即返回顺序 |

匹配优先级（逐级决胜）：

1. **前缀长度最长者胜**；
2. 前缀长度相同 → **deny 胜过 allow**；
3. 仍相同（同一列表内的重复项）→ 按该列表中的**原顺序**取第一条；
4. 没有任何条目包含该地址 → `unmatched`。

示例：

```bash
curl -s -X POST http://localhost:8000/evaluate \
  -H 'Content-Type: application/json' \
  -d '{
        "allow": ["10.0.0.0/24", "10.0.0.0/25", "2001:db8::/32"],
        "deny":  ["10.0.0.0/25"],
        "addresses": ["10.0.0.1", "10.0.0.200", "192.0.2.1", "2001:db8::1"]
      }'
```

响应（与 `addresses` 等长、同序）：

```json
[
  {"decision": "deny",      "matched_cidr": "10.0.0.0/25", "matched_side": "deny"},
  {"decision": "allow",     "matched_cidr": "10.0.0.0/24", "matched_side": "allow"},
  {"decision": "unmatched", "matched_cidr": null,           "matched_side": null},
  {"decision": "allow",     "matched_cidr": "2001:db8::/32", "matched_side": "allow"}
]
```

字段说明：

- `decision`：`allow` / `deny` / `unmatched`；
- `matched_cidr`：获胜条目的规范 CIDR（裸地址条目规范化为主机前缀
  `10.0.0.1/32`），未匹配时为 `null`；
- `matched_side`：获胜条目来自 `allow` 还是 `deny`，未匹配时为 `null`。

非法 CIDR 或非法地址（包括给 `addresses` 传入 `10.0.0.1/24` 这样的 CIDR
记法）统一返回 **HTTP 422**。

### `POST /compare`

在**单个 `scope` CIDR** 范围内，比较 **baseline（基线）** 与
**candidate（候选）** 两组 allow/deny 策略的判定差异。两组策略各自沿用
`/evaluate` 的**最长前缀、同长度 deny 优先**规则。

请求体：

| 字段        | 类型       | 说明                                   |
| ----------- | ---------- | -------------------------------------- |
| `scope`     | `string`   | **必填**，单个 CIDR（IPv4 或 IPv6），限定比较区域；主机位非零返回 422 |
| `baseline`  | `object`   | 基线策略，形如 `{"allow": [...], "deny": [...]}`，省略视为两个空列表 |
| `candidate` | `object`   | 候选策略，结构同 `baseline`            |

处理过程：

1. 分别把 scope 对 baseline、candidate **递归切分为判定恒定的互不重叠
   CIDR**（只有更具体的条目边界才触发对半拆分）；
2. **叠加（求交）两侧分区**，只保留两侧判定不同的区域；
3. 对差异区域中**相邻且转换类型相同的完整兄弟网段递归合并**（转换不同的
   兄弟、不等长的相邻网段不合并）。

示例：

```bash
curl -s -X POST http://localhost:8000/compare \
  -H 'Content-Type: application/json' \
  -d '{
        "scope": "10.0.0.0/24",
        "baseline":  {"allow": ["10.0.0.0/24"], "deny": []},
        "candidate": {"allow": ["10.0.0.0/25"], "deny": ["10.0.0.128/26"]}
      }'
```

响应（按 IPv4→IPv6、网络地址、前缀长度稳定排序）：

```json
{
  "differences": [
    {"cidr": "10.0.0.128/26", "baseline_decision": "allow", "candidate_decision": "deny"},
    {"cidr": "10.0.0.192/26", "baseline_decision": "allow", "candidate_decision": "unmatched"}
  ],
  "transition_counts": {
    "allow->deny": "64",
    "allow->unmatched": "64",
    "deny->allow": "0",
    "deny->unmatched": "0",
    "unmatched->allow": "0",
    "unmatched->deny": "0"
  }
}
```

字段说明：

- `differences[].cidr`：判定发生变化的互不重叠区域；
- `differences[].baseline_decision` / `candidate_decision`：该区域内
  恒定的两侧判定，取值 `allow` / `deny` / `unmatched`，二者必不相同；
- `transition_counts`：六种转换类型 `"baseline->candidate"` 各自覆盖的
  **地址数（十进制字符串）**，未出现的转换为 `"0"`；计数与
  `differences` 覆盖的地址一一对应（例如两个 `/26` 各 64 个地址）。

说明：

- 与 scope 不同地址族的条目自动忽略；等于或包含 scope 的条目在整个
  scope 上生效（例如 scope 为 `10.0.0.0/25` 时，两侧相同的
  `10.0.0.0/24` 不产生差异）；
- 两组策略完全一致（或 scope 内判定一致）时 `differences` 为空数组；
- `scope` 缺失、非法、主机位非零，或嵌套的 baseline/candidate 中存在
  非法 CIDR，统一返回 **HTTP 422**。

### `POST /audit-rules`

在**单个 `scope` CIDR** 内，接收现有 allow/deny 两个列表，**按输入侧与原序**
逐条审计每条规则是否真正影响最终判定。判定规则沿用 `/evaluate`：

1. **前缀长度最长者胜**；
2. 前缀长度相同 → **deny 胜过 allow**；
3. 仍相同（同一列表内的重复项）→ 按该列表中的**原顺序**取第一条（重复规则
   的稳定优先级）。

分析完全基于 **CIDR 分区**（自 scope 起递归对半切分，只按网段集合运算），
**不枚举任何地址**，因此兼容巨大 IPv6 网段（如 `::/0`），也兼容 IPv4。

请求体：

| 字段    | 类型       | 说明                                   |
| ------- | ---------- | -------------------------------------- |
| `scope` | `string`   | **必填**，单个 CIDR（IPv4 或 IPv6），限定审计区域；主机位非零返回 422 |
| `allow` | `string[]` | 允许列表，可省略（默认 `[]`）；每条必须与 scope **同地址族** |
| `deny`  | `string[]` | 拒绝列表，规则同 `allow`               |

每条规则的审计结论（`status`）：

- **`effective`**：规则在 scope 内**至少赢下一个区域**（对该区域内地址起决定
  作用）。响应给出 `witness`：该规则获胜区域内**数值最小的网络地址**（裸 IP
  字符串，IPv6 采用压缩写法）；它一定落在获胜区域内，且位于某个分区网段的
  边界上，无需枚举地址即可算出。
- **`shadowed`**：规则与 scope 相交，但在 scope 内**处处无法获胜**。响应给出
  `shadowed_by`：**真正赢下其区域各部分的规则的 `(side, index)` 集合**（去重、
  按 side、index 排序）；只有自己也能获胜的规则才会出现——本身也被遮蔽的死
  规则不会被列入。`index` 为该规则在对应输入列表中的 **0 基下标**。
- **`out_of_scope`**：规则 CIDR 与 scope **完全不相交**（同地址族但无交集），
  对 scope 内判定没有任何影响。大于等于 scope 的规则按 scope 裁剪后的区域
  分析；裸地址按 `/32`、`/128` 处理。

> 注意：与 `/compare` 静默忽略异地址族条目的策略不同，`/audit-rules` 中任何
> 规则与 scope **地址族不一致都直接返回 422**。

示例：

```bash
curl -s -X POST http://localhost:8000/audit-rules \
  -H 'Content-Type: application/json' \
  -d '{
        "scope": "10.0.0.0/24",
        "allow": [
          "10.0.0.0/24",
          "10.0.0.0/25",
          "10.0.0.0/25"
        ],
        "deny": [
          "10.0.0.0/25",
          "10.1.0.0/16"
        ]
      }'
```

响应（`allow` / `deny` 各自与输入**等长、同序**）：

```json
{
  "allow": [
    {"side": "allow", "index": 0, "cidr": "10.0.0.0/24",
     "status": "effective", "witness": "10.0.0.128", "shadowed_by": null},
    {"side": "allow", "index": 1, "cidr": "10.0.0.0/25",
     "status": "shadowed", "witness": null,
     "shadowed_by": [{"side": "deny", "index": 0}]},
    {"side": "allow", "index": 2, "cidr": "10.0.0.0/25",
     "status": "shadowed", "witness": null,
     "shadowed_by": [{"side": "deny", "index": 0}]}
  ],
  "deny": [
    {"side": "deny", "index": 0, "cidr": "10.0.0.0/25",
     "status": "effective", "witness": "10.0.0.0", "shadowed_by": null},
    {"side": "deny", "index": 1, "cidr": "10.1.0.0/16",
     "status": "out_of_scope", "witness": null, "shadowed_by": null}
  ]
}
```

字段说明：

- `side` / `index` / `cidr`：规则来源侧（`allow` / `deny`）、在该侧输入列表中
  的 0 基下标、规范 CIDR；
- `status`：`effective` / `shadowed` / `out_of_scope`；
- `witness`：仅 `effective` 时出现，为该规则获胜区域内数值最小的 IP（上例中
  allow `/24` 只在高地址半区 `10.0.0.128/25` 获胜，故 witness 为
  `10.0.0.128` 而非规则自身起点 `10.0.0.0`）；
- `shadowed_by`：仅 `shadowed` 时出现，为赢下该规则区域各部分的规则引用集合；
  上例中两条重复的 allow `/25`（index 1、2）都在同长度对决中败给
  deny index 0，故二者 `shadowed_by` 相同。

`scope` 缺失/非法/主机位非零、规则 CIDR 非法，或规则与 scope 地址族不一致，
统一返回 **HTTP 422**。

### `POST /minimize-policy`

在**单个 `scope` CIDR** 内，接收合计**不超过 16 条**的 allow/deny 规则，求出
一个规则子集，使其对 scope 内**每个地址的判定都与原策略完全一致**，且子集的
规则数**最少**。判定规则沿用 `/evaluate`（最长前缀 → 同长度 deny 优先 →
同列表原序优先）。

算法基于 **CIDR 分区**（自 scope 起递归对半切分，只做网段运算）配合
**精确的分支限界子集搜索**：先按原策略把 scope 切成获胜者恒定的最大 CIDR 瓦片，
再以“最受限瓦片优先 + 强制纳入/排除规则”的深度优先搜索枚举可行子集——
**既不枚举任何 IP 地址，也不采用逐条贪心删除**（逐条贪心无法保证全局最少），
因此可处理 `::/0` 这类巨大 IPv6 scope。多组同样最少的解，按保留规则的
`(side, index)` 序列取**字典序最小**的唯一结果（`allow` 排在 `deny` 前，
两侧各自按原下标升序）。

请求体：

| 字段    | 类型       | 说明                                   |
| ------- | ---------- | -------------------------------------- |
| `scope` | `string`   | **必填**，单个 CIDR（IPv4 或 IPv6），限定最小化区域；主机位非零返回 422 |
| `allow` | `string[]` | 允许列表，可省略（默认 `[]`）；每条必须与 scope **同地址族** |
| `deny`  | `string[]` | 拒绝列表，规则同 `allow`               |

> `allow` 与 `deny` 的**总条数不得超过 16**，否则返回 422；任一规则与 scope
> 地址族不一致同样返回 422。

示例：

```bash
curl -s -X POST http://localhost:8000/minimize-policy \
  -H 'Content-Type: application/json' \
  -d '{
        "scope": "10.0.0.0/24",
        "allow": ["10.0.0.0/24", "10.0.0.0/25"],
        "deny":  ["10.0.0.128/25"]
      }'
```

原策略：低地址半区 `10.0.0.0/25` 由 allow 获胜（allow `/25` 与 `/24` 同覆盖时
取更长的 `/25`，但二者判定相同），高地址半区 `10.0.0.128/25` 由 deny 获胜。
allow index 1（`/25`）是多余的——保留更宽的 allow index 0（`/24`）即可覆盖低
半区且在高半区输给 deny。响应：

```json
{
  "retained": [
    {"side": "allow", "index": 0, "cidr": "10.0.0.0/24", "witness": "10.0.0.0"},
    {"side": "deny", "index": 0, "cidr": "10.0.0.128/25", "witness": "10.0.0.128"}
  ],
  "removed": [
    {"side": "allow", "index": 1, "cidr": "10.0.0.0/25"}
  ]
}
```

字段说明：

- `retained` / `removed`：**保留 / 删除的规则引用**，均按**原输入顺序**返回——
  先按 index 列出全部 allow 引用，再按 index 列出全部 deny 引用；两组合起来恰好
  是全部输入规则且互不重叠；
- 每条引用含 `side`（`allow` / `deny`）、`index`（该侧输入列表中的 0 基下标）、
  `cidr`（规范 CIDR）；
- `retained[]` 额外含 `witness`：该规则在**最小方案**中获胜区域内**数值最小的
  IP 地址**（它由最小方案自身的获胜者分区算出，可能落在分区边界上，无需枚举地址；
  IPv6 采用压缩写法）。`removed[]` 不含 `witness`。

其他要点：

- 与 scope 完全不相交的规则不影响任何判定，一律进入 `removed`；
- 同长度被 deny 压制的 allow、同侧被更早重复项遮蔽的规则等“从不获胜”的规则都会
  被删除；
- 若存在多组等大的最少解（例如宽 `/24` 与窄 `/25` 两条 allow 都能配合同一条
  deny 构成二规则解），按保留规则的 `(side, index)` 序列字典序取唯一结果，
  上例即保留 `("allow", 0)` 而非 `("allow", 1)`；
- 空策略（无规则）返回 `{"retained": [], "removed": []}`；
- 规则总数超过 16、`scope` 缺失/非法/主机位非零、规则 CIDR 非法，或规则与 scope
  地址族不一致，统一返回 **HTTP 422**。

### `POST /allocate`

在**单个 `scope` CIDR** 内，为多条子网申请分配**互不重叠、且不触碰占用
网段**的子网。按申请顺序把各分配结果的网络地址组成序列，返回**字典序最小
的完整可行方案**——靠前的申请优先占据低地址，必要时自动回溯；任一申请
无法满足时返回 **HTTP 409**，且不返回任何部分分配。

请求体：

| 字段                     | 类型       | 说明                                   |
| ------------------------ | ---------- | -------------------------------------- |
| `scope`                  | `string`   | **必填**，单个 CIDR（IPv4 或 IPv6），分配范围；主机位非零返回 422 |
| `occupied`               | `string[]` | 已占用 CIDR 列表，可省略（默认 `[]`）。每条必须与 scope **同地址族**、**位于 scope 内**且**互不重叠**，否则 422 |
| `requests`               | `object[]` | 申请列表，按此顺序分配，可省略（默认 `[]`） |
| `requests[].id`          | `string`   | 申请标识，非空且**不可重复**（重复返回 422） |
| `requests[].prefix_length` | `int`    | 申请的前缀长度；IPv4 为 0–32、IPv6 为 0–128，越界返回 422 |

说明：

- `prefix_length` **小于 scope 前缀长度**（如 /24 scope 里申请 /16）不属于
  非法输入，而是**永远无法满足的申请**，按 409 处理；
- 分配结果彼此不重叠、不碰 `occupied`，且都是 scope 的子网；
- 响应中的 `allocations` **保持申请顺序**（不是地址顺序）。

示例（需要回溯的情形：若把 `small` 贪心地放进低地址的 /25，`big` 的 /24
将无处安放；搜索回溯后把 `small` 挪到 `10.0.1.128/25`）：

```bash
curl -s -X POST http://localhost:8000/allocate \
  -H 'Content-Type: application/json' \
  -d '{
        "scope": "10.0.0.0/23",
        "occupied": ["10.0.1.0/25"],
        "requests": [
          {"id": "small", "prefix_length": 25},
          {"id": "big",   "prefix_length": 24}
        ]
      }'
```

响应：

```json
{
  "allocations": [
    {"id": "small", "cidr": "10.0.1.128/25"},
    {"id": "big",   "cidr": "10.0.0.0/24"}
  ],
  "remaining": [],
  "remaining_addresses": "0"
}
```

字段说明：

- `allocations`：与 `requests` 等长、同序的分配结果，`cidr` 为规范 CIDR；
- `remaining`：分配后 scope 内剩余空间的**最小 CIDR 集合**（互不重叠、
  按网络地址排序）；
- `remaining_addresses`：剩余地址总数，**十进制字符串**（IPv6 下会超出
  JSON 安全整数范围，与 `/compare` 的计数口径一致）。

无法满足时返回 409，响应体不含任何分配结果：

```bash
curl -i -X POST http://localhost:8000/allocate \
  -H 'Content-Type: application/json' \
  -d '{
        "scope": "10.0.0.0/24",
        "occupied": ["10.0.0.0/25"],
        "requests": [
          {"id": "x", "prefix_length": 25},
          {"id": "y", "prefix_length": 25}
        ]
      }'
# HTTP/1.1 409 Conflict
# {"detail":"no complete allocation satisfies all requests within scope
#   '10.0.0.0/24'; no partial allocation returned"}
```

重复 id、越界前缀长度、非法网段（格式错误、主机位非零、与 scope 不同族、
超出 scope、占用列表互相重叠）统一返回 **HTTP 422**。

### `POST /anonymize`

共享地址清单时，对**裸 IPv4/IPv6 地址**与**严格 CIDR** 做**前缀保持的密钥
脱敏**。请求携带一个 64 位十六进制字符（256 bit）的 `key_hex`：同一密钥下
映射**稳定**且在整个地址族上**一一对应**（双射），任意两个地址的**最长公共
前缀长度保持不变**，因此脱敏后的地址清单仍保留聚类、邻接与网段归属关系，
但无法直接读出原始地址。

请求体：

| 字段        | 类型       | 说明                                   |
| ----------- | ---------- | -------------------------------------- |
| `key_hex`   | `string`   | **必填**，恰好 64 个十六进制字符（256 bit），大小写均可 |
| `addresses` | `string[]` | 待脱敏的**裸 IP 地址**（不接受 CIDR 记法），可省略（默认 `[]`），顺序即返回顺序 |
| `cidrs`     | `string[]` | 待脱敏的**严格 CIDR**（必须显式带前缀长度、主机位为零），可省略（默认 `[]`），顺序即返回顺序 |

算法按**网络位序（最高位在前）逐位处理**。对第 `i` 位（从 0 起），以
HMAC-SHA256（密钥即 `key_hex` 解码出的 32 字节）计算消息：

1. **地址族标记字节**：IPv4 为 `0x04`、IPv6 为 `0x06`（两族互不串用）；
2. **当前位序字节**：单字节整数 `i`；
3. **此前原始位补零串**：把该地址**原始**的前 `i` 位放在最前，右侧补零到地址
   全长（IPv4 为 4 字节、IPv6 为 16 字节）。

取摘要的**最高位**与当前原始位**异或**得到脱敏位。由于补零串在每一位上只
包含此前的原始位，公共前缀上每一步 HMAC 输入完全相同（前缀保持）；每个前缀
节点的两个出口位在同一异或掩码下仍互不相同（一一对应）；密钥固定则逐位决策
固定（稳定）。CIDR 先对其**网络地址**脱敏，再按**原前缀长度**把主机位清零，
返回规范网段（前缀长度不变）。

示例（服务默认监听 <http://localhost:8000>）：

```bash
curl -s -X POST http://localhost:8000/anonymize \
  -H 'Content-Type: application/json' \
  -d '{
        "key_hex": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "addresses": ["10.0.0.1", "10.0.0.2", "192.0.2.1", "2001:db8::1"],
        "cidrs": ["10.0.0.0/24", "2001:db8::/32"]
      }'
```

响应（`addresses` / `cidrs` 分别与各自输入**等长、同序**）：

```json
{
  "addresses": [
    "77.249.170.48",
    "77.249.170.51",
    "236.60.54.68",
    "d5af:46c8:beb3:e56d:c681:ca26:c4a4:9e2a"
  ],
  "cidrs": ["77.249.170.0/24", "d5af:46c8::/32"]
}
```

上例中 `10.0.0.1` 与 `10.0.0.2` 的最长公共前缀为 `/30`，脱敏后的
`77.249.170.48` 与 `77.249.170.51` 最长公共前缀同样是 `/30`，且二者都落在
脱敏网段 `77.249.170.0/24` 内；`2001:db8::/32` 脱敏为 `d5af:46c8::/32`，
前缀长度不变。更换 `key_hex` 即得到完全不同的映射；相同密钥重复请求结果一致。

字段说明：

- `addresses`：脱敏后的裸地址，IPv4/IPv6 可混填，保持 `addresses` 输入顺序；
- `cidrs`：脱敏后的规范网段，保持 `cidrs` 输入顺序与各自**原前缀长度**。

`key_hex` 不是 64 个十六进制字符、`addresses` 中出现非法地址或 CIDR 记法、
`cidrs` 中出现非法网段、缺少显式前缀长度（裸地址）或**主机位非零**
（如 `10.0.0.1/24`），统一返回 **HTTP 422**。

### `POST /reverse-delegations`

为**同一个父 `/24`** 内的多个 IPv4 网段生成反向 DNS（`in-addr.arpa`）
委派计划。每个条目给出一个**严格 CIDR（必须显式带前缀、主机位为零）**
及其 NS 域名列表；只接受 **`/24`～`/32`** 的 IPv4 网段：

- **`/24`**：直接委派该网段对应的反向区域
  `d.c.b.a.in-addr.arpa.`，在区域顶点生成 **NS 记录**；
- **`/25`～`/32`**：反向区域无法按传统分类网络切分，按
  **RFC 2317** 处理——以范围标签
  **`<网络地址末段>/<前缀长度>`**（如 `10.0.0.128/26` → `128/26`、
  `10.0.0.5/32` → `5/32`）在父 `/24` 区域之下命名一个可委派子区，为子区
  生成 **NS 记录**，并由**父区为覆盖的每一个地址**生成一条 **CNAME**：
  `n.d.c.b.a.in-addr.arpa.` → `n.<标签>.d.c.b.a.in-addr.arpa.`，即委派子区
  内负责该地址的 PTR 名称。

请求体：

| 字段                          | 类型       | 说明                                   |
| ----------------------------- | ---------- | -------------------------------------- |
| `delegations`                 | `object[]` | 委派条目列表，可省略（默认 `[]`）       |
| `delegations[].cidr`          | `string`   | **严格 IPv4 CIDR**，仅 `/24`～`/32`；必须显式带前缀，主机位非零返回 422 |
| `delegations[].nameservers`   | `string[]` | NS 域名列表，**至少一个**；大小写不敏感、自动补根点，重复目标只生成一条 NS |

整批约束（违反任一即**整批拒绝**、返回 **HTTP 422**，不返回任何部分计划）：

- 所有网段必须位于**同一个父 `/24`** 内；
- 任意两个网段**不得相交**（因此一个 `/24` 条目不能与该 `/24` 内的任何其它
  网段同批出现——它覆盖整个父区；不相交的 `/25`～`/32` 子区可任意组合）。

示例一：`/24` 直接委派。

```bash
curl -s -X POST http://localhost:8000/reverse-delegations \
  -H 'Content-Type: application/json' \
  -d '{
        "delegations": [
          {"cidr": "192.0.2.0/24",
           "nameservers": ["ns1.example.net", "ns2.example.net"]}
        ]
      }'
```

响应：

```json
{
  "zones": [
    {
      "zone": "2.0.192.in-addr.arpa.",
      "method": "direct",
      "parent_zone": null,
      "cidr": "192.0.2.0/24",
      "nameservers": ["ns1.example.net.", "ns2.example.net."]
    }
  ],
  "records": [
    {"zone": "2.0.192.in-addr.arpa.", "type": "NS",
     "name": "2.0.192.in-addr.arpa.", "target": "ns1.example.net.",
     "cidr": "192.0.2.0/24"},
    {"zone": "2.0.192.in-addr.arpa.", "type": "NS",
     "name": "2.0.192.in-addr.arpa.", "target": "ns2.example.net.",
     "cidr": "192.0.2.0/24"}
  ]
}
```

示例二：同一 `/24` 内两个不相交的小子网按 RFC 2317 委派（输入顺序随意，
输出统一按网络地址排序）。

```bash
curl -s -X POST http://localhost:8000/reverse-delegations \
  -H 'Content-Type: application/json' \
  -d '{
        "delegations": [
          {"cidr": "10.0.0.128/30",
           "nameservers": ["ns1.cust.example", "ns2.cust.example"]},
          {"cidr": "10.0.0.5/32",
           "nameservers": ["host-5.example.org"]}
        ]
      }'
```

响应（节选；`128/30` 实际为 2 条 NS + 4 条 CNAME，此处仅展示首尾）：

```json
{
  "zones": [
    {"zone": "5/32.0.0.10.in-addr.arpa.", "method": "rfc2317",
     "parent_zone": "0.0.10.in-addr.arpa.", "cidr": "10.0.0.5/32",
     "nameservers": ["host-5.example.org."]},
    {"zone": "128/30.0.0.10.in-addr.arpa.", "method": "rfc2317",
     "parent_zone": "0.0.10.in-addr.arpa.", "cidr": "10.0.0.128/30",
     "nameservers": ["ns1.cust.example.", "ns2.cust.example."]}
  ],
  "records": [
    {"zone": "0.0.10.in-addr.arpa.", "type": "NS",
     "name": "5/32.0.0.10.in-addr.arpa.", "target": "host-5.example.org.",
     "cidr": "10.0.0.5/32"},
    {"zone": "0.0.10.in-addr.arpa.", "type": "CNAME",
     "name": "5.0.0.10.in-addr.arpa.",
     "target": "5.5/32.0.0.10.in-addr.arpa.", "cidr": "10.0.0.5/32"},
    {"zone": "0.0.10.in-addr.arpa.", "type": "NS",
     "name": "128/30.0.0.10.in-addr.arpa.", "target": "ns1.cust.example.",
     "cidr": "10.0.0.128/30"},
    {"zone": "0.0.10.in-addr.arpa.", "type": "CNAME",
     "name": "128.0.0.10.in-addr.arpa.",
     "target": "128.128/30.0.0.10.in-addr.arpa.", "cidr": "10.0.0.128/30"}
  ]
}
```

字段说明：

- `zones[]`：每个输入网段一个委派区，按**网络地址、前缀长度**排序；
  - `zone`：委派区 FQDN（直接委派时即 `in-addr.arpa` 区，RFC 2317 时为
    范围标签子区）；
  - `method`：`direct`（`/24`）或 `rfc2317`（`/25`～`/32`）；
  - `parent_zone`：RFC 2317 时发布 CNAME 的父 `/24` 反向区；直接委派为
    `null`；
  - `cidr`：产生该区的**输入网段（规范化 CIDR）**，保留输入与输出的对应；
  - `nameservers`：规范化（小写、单一根点）去重后的 NS 目标，按首次出现顺序。
- `records[]`：待发布的 NS / CNAME 记录，按**来源网段网络地址**排序，同一
  网段的记录连续成组，组内 **NS 在前、CNAME 按地址末段升序在后**；
  - 直接委派的 NS 记录 `zone` 即该反向区本身；RFC 2317 的 NS 与 CNAME
    记录 `zone` 均为**父 `/24` 区**（由父区发布委派与别名）；
  - 每条记录都带 `cidr` 字段标明它由哪个**输入网段**生成。

网段相交或不在同一 `/24` 时整批返回 422：

```bash
curl -i -X POST http://localhost:8000/reverse-delegations \
  -H 'Content-Type: application/json' \
  -d '{"delegations": [
        {"cidr": "10.0.0.0/25", "nameservers": ["ns1.example.net"]},
        {"cidr": "10.0.0.64/26", "nameservers": ["ns2.example.net"]}
      ]}'
# HTTP/1.1 422 Unprocessable Entity
# {"detail":[{"type":"value_error","loc":["body"],
#   "msg":"Value error, reverse-delegation CIDRs 10.0.0.0/25 and 10.0.0.64/26
#          overlap; the whole batch is rejected", ...}]}
```

非法地址族（IPv6）、前缀短于 `/24`（或长于 `/32`、越界）、缺少显式前缀
（裸地址）、主机位非零、NS 域名非法（含裸 IP 地址）或 NS 列表为空，
统一返回 **HTTP 422**。空批次（`{}`）合法，返回两个空数组。

### `POST /roa-coverage`

在**单个 `scope` CIDR** 内，针对拟以某个 ASN 发布的**固定前缀长度**
（`prefix_length`），枚举该长度下 scope 内所有**对齐候选路由**，按 ROA
（Route Origin Authorization）列表逐条判定 RPKI 起源授权状态（RFC 6483）：

- **`valid`（有效）**：存在至少一条覆盖该候选前缀的 ROA，其 **ASN 等于
  目标 ASN**，且 **`max_length` 不小于拟发布前缀长度**；
- **`invalid`（无效）**：至少有一条 ROA 覆盖该候选前缀，但**没有任何一条**
  同时满足 ASN 与 `max_length` 授权——包括「来源 ASN 错误」与
  「前缀比授权的 `max_length` 更长（length-invalid）」两种情形；
- **`unknown`（未知）**：**没有任何 ROA** 的前缀包含该候选路由。

响应不是逐路由的庞大清单，而是把状态相同的相邻路由合并后的
**最小 CIDR 状态分区**：按网络地址排序、互不重叠且恰好铺满整个候选区域；
每个分区可**短于（前缀号小于）拟发布长度**，表示其中所有该长度的候选路由
状态一致。算法只沿 ROA 前缀边界自 scope 起递归对半切分，
**绝不逐个枚举候选子网**，因此 `::/0` scope、`/128` 候选这类
$2^{128}$ 条路由的情形也是毫秒级返回若干个 CIDR 分区。

请求体：

| 字段              | 类型       | 说明                                   |
| ----------------- | ---------- | -------------------------------------- |
| `scope`           | `string`   | **必填**，单个严格 CIDR（IPv4 或 IPv6），限定分析区域；主机位非零返回 422 |
| `asn`             | `int`      | **必填**，拟发布路由的目标 32 位 ASN（0～4294967295），越界返回 422 |
| `prefix_length`   | `int`      | **必填**，拟发布前缀长度；不得短于 scope 前缀，且 IPv4 不超过 32、IPv6 不超过 128，越界返回 422 |
| `roas`            | `object[]` | ROA 列表，可省略（默认 `[]`）；每条必须与 scope **同地址族**，与 scope 不相交的 ROA 会被忽略 |
| `roas[].cidr`     | `string`   | **严格 CIDR**：必须显式带 `/p`、主机位为零；裸地址、主机位非零返回 422 |
| `roas[].asn`      | `int`      | 该 ROA 授权的 32 位 ASN（0～4294967295） |
| `roas[].max_length` | `int`    | 该 ROA 允许的最长前缀；必须满足 **ROA 前缀长度 ≤ `max_length` ≤ 地址族上限**（IPv4 为 32、IPv6 为 128），否则 422 |

示例（`/25` ROA 授权 `max_length 26`，一次性覆盖两个 `/26` 候选；另有一条
错误 ASN 的 ROA 与一段完全无人覆盖的区域）：

```bash
curl -s -X POST http://localhost:8000/roa-coverage \
  -H 'Content-Type: application/json' \
  -d '{
        "scope": "203.0.113.0/24",
        "asn": 64500,
        "prefix_length": 26,
        "roas": [
          {"cidr": "203.0.113.0/25", "asn": 64500, "max_length": 26},
          {"cidr": "203.0.113.128/26", "asn": 64501, "max_length": 26}
        ]
      }'
```

响应：低地址半区的两个 `/26` 候选同被一条 `/25` ROA 授权，合并成一个
**短于拟发布长度**的 `203.0.113.0/25`（valid）分区：

```json
{
  "partitions": [
    {"cidr": "203.0.113.0/25", "status": "valid"},
    {"cidr": "203.0.113.128/26", "status": "invalid"},
    {"cidr": "203.0.113.192/26", "status": "unknown"}
  ]
}
```

`max_length` 不足时整个区域判 invalid 并向上合并的示例（拟发布 `/25`，
但 ROA 只授权到 `/24`，两个候选都 length-invalid，合并为单个 `/24`）：

```bash
curl -s -X POST http://localhost:8000/roa-coverage \
  -H 'Content-Type: application/json' \
  -d '{
        "scope": "203.0.113.0/24",
        "asn": 64500,
        "prefix_length": 25,
        "roas": [
          {"cidr": "203.0.113.0/24", "asn": 64500, "max_length": 24}
        ]
      }'
# {"partitions": [{"cidr": "203.0.113.0/24", "status": "invalid"}]}
```

IPv6 超大范围示例（不枚举任何子网；返回的少量 CIDR 分区恰好铺满
$2^{128}$ 地址空间）：

```bash
curl -s -X POST http://localhost:8000/roa-coverage \
  -H 'Content-Type: application/json' \
  -d '{
        "scope": "::/0",
        "asn": 64500,
        "prefix_length": 128,
        "roas": [
          {"cidr": "2001:db8::/32", "asn": 64500, "max_length": 128},
          {"cidr": "2001:db9::/32", "asn": 64501, "max_length": 48}
        ]
      }'
# 2001:db8::/32 -> valid；2001:db9::/32 -> invalid（ASN 错误且 /128 超 max_length）；
# 其余整个 IPv6 空间合并为少量 unknown 分区。
```

字段说明：

- `partitions[].cidr`：状态恒定的最小分区 CIDR，前缀长度满足
  `scope 前缀 ≤ 分区前缀 ≤ prefix_length`，各分区互不重叠、联合铺满 scope；
- `partitions[].status`：该分区内**每一条**对齐候选路由共同的状态，
  取值 `valid` / `invalid` / `unknown`。

其他要点：

- 与 scope **同地址族但不相交**的 ROA 不影响任何候选，直接忽略；
- **ROA 前缀比候选粒度更细**（例如候选 `/24`、ROA 是 `/32`）时，该 ROA
  整个落在单个候选内部，按 RFC 6483 它**并不覆盖**该候选（覆盖要求候选是
  ROA 前缀的子网），因此不参与判定；
- 无任何 ROA 时整个 scope 为单个 `unknown` 分区；全部覆盖且无授权时为
  单个 `invalid` 分区；
- `scope` 缺失/非法/主机位非零、`prefix_length` 越界（超过地址族上限）或
  **短于 scope 前缀**、`asn` 越界、ROA 为**跨地址族**、ROA CIDR 非法
  （含裸地址、主机位非零）、ROA `asn` 越界或 `max_length` 不在
  「ROA 前缀长度～地址族上限」区间内，统一返回 **HTTP 422**。

### `POST /as-relationship-repair`

接收**至多 9 条无向 AS 关系**与**至多 20 条按起源到接收方向排列的 AS 路径**，
允许把任意一条关系改成**另一种客户-提供商方向**或**对等关系**，以**改动的
关系条数最少**为目标，使全部路径同时满足 BGP 的**无谷（valley-free）规则**：
沿路径方向，各跳关系必须形如

> **上行（客户→提供商）零次或多次 → 对等至多一次 → 下行（提供商→客户）零次或多次**

即一旦走过对等跳或下行跳，就不能再上行；对等跳至多一次。同一条无向关系在
所有路径中**共用同一个修正结果**；任何路径没有用到的关系不会被改动，也不
参与搜索。

请求体：

| 字段 | 类型 | 说明 |
| ---- | ---- | ---- |
| `relationships` | `object[]` | 无向 AS 关系列表，至多 **9** 条，可省略（默认 `[]`）；同一 AS 对至多出现一次，否则 422 |
| `relationships[].type` | `string` | `customer_provider`（客户-提供商，有方向）或 `peer`（对等，无方向） |
| `relationships[].customer` | `int` | 客户 ASN（32 位，0～4294967295）；`customer_provider` 时必填，且与 `provider` 不同 |
| `relationships[].provider` | `int` | 提供商 ASN；`customer_provider` 时必填 |
| `relationships[].peers` | `int[]` | 恰好两个不同的对等 ASN（顺序任意）；`peer` 时必填 |
| `paths` | `int[][]` | 起源→接收 AS 路径列表，至多 **20** 条，可省略（默认 `[]`）。每条路径非空、**无重复 AS**，且**每一跳的 AS 对都必须在 `relationships` 中有关系**，否则 422；单 AS 路径（0 跳）天然合规 |

示例（两条路径在 AS 200 处形成相同的「下行后上行」山谷；把它们共用的
`200/300` 关系反转为「300 是客户、200 是提供商」，一条改动同时修好两条路径；
服务默认监听 <http://localhost:8000>）：

```bash
curl -s -X POST http://localhost:8000/as-relationship-repair \
  -H 'Content-Type: application/json' \
  -d '{
        "relationships": [
          {"type": "customer_provider", "customer": 200, "provider": 100},
          {"type": "customer_provider", "customer": 200, "provider": 300},
          {"type": "customer_provider", "customer": 200, "provider": 400}
        ],
        "paths": [
          [100, 200, 300],
          [400, 200, 300]
        ]
      }'
```

原关系下：

- 路径 `100 → 200`：100 是提供商、200 是客户，为**下行**；`200 → 300`：
  200 是客户、300 是提供商，为**上行**——下行后上行，成谷，违规；
- 路径 `400 → 200 → 300` 同理（下行后上行），也违规。

把 `200/300` 反转为客户 300、提供商 200 后，两条路径都变成纯**下行**，
一次改动全部合规。响应：

```json
{
  "violating_path_indices": [0, 1],
  "corrections": [
    {"type": "customer_provider", "customer": 300, "provider": 200, "peers": null}
  ],
  "changes": 1
}
```

字段说明：

- `violating_path_indices`：在**改动前**的原关系下违反无谷规则的路径下标
  （0 基，按升序）；全部合规时为 `[]`；
- `corrections`：唯一最少方案中**被改动的关系**，结构与输入关系相同
  （`customer_provider` 携带 `customer`/`provider` 且 `peers` 为 `null`；
  `peer` 携带两个 `peers`），按规范化 AS 对（较小 ASN 在前）排序；
- `changes`：改动的关系条数，即 `len(corrections)`；全部路径已合规时为
  `0`，`corrections` 为空数组。

同分决胜：当存在多组同样改动最少的方案时，把各路径用到的无向关系按
规范化 AS 对（`(lo, hi)`，`lo < hi`）排序，取修复后每条关系的**新关系
序列**（客户为 `lo` 的客户-提供商 → 客户为 `hi` 的客户-提供商 → 对等）
**字典序最小**的唯一方案。例如下谷路径 `100 → 200 → 300` 的两条边各可
反转一次完成修复时，序列中更靠前的 `(100,200)` 被优先改动。

无可行方案时返回 **409**（4 条路径对 5 条关系的方向/对等要求两两矛盾，
任意 3 条路径的子集都仍可修复）：

```bash
curl -i -X POST http://localhost:8000/as-relationship-repair \
  -H 'Content-Type: application/json' \
  -d '{
        "relationships": [
          {"type": "customer_provider", "customer": 1, "provider": 2},
          {"type": "customer_provider", "customer": 3, "provider": 1},
          {"type": "peer", "peers": [1, 4]},
          {"type": "customer_provider", "customer": 2, "provider": 3},
          {"type": "customer_provider", "customer": 4, "provider": 3}
        ],
        "paths": [
          [4, 3, 2, 1],
          [2, 1, 3, 4],
          [4, 1, 3, 2],
          [3, 4, 1, 2]
        ]
      }'
# HTTP/1.1 409 Conflict
# {"detail":"no assignment of the supplied relationships makes every AS path
#   valley-free (up*, at most one peer, down*)"}
```

以下输入统一返回 **HTTP 422**：关系或路径超过条数上限；关系 `type` 非法、
`customer_provider` 缺 `customer`/`provider` 或两端相同、误带 `peers`；
`peer` 缺 `peers`、`peers` 不是恰好两个不同 ASN、误带 `customer`/`provider`；
ASN 非整数（含布尔值）或超出 32 位范围；同一 AS 对重复给出关系（冲突）；
路径为空、路径内 AS 重复，或某一跳的 AS 对没有任何关系。

### `POST /nat64-codec`

按 **RFC 6052**（Network-Specific IPv4/IPv6 Translators）在一个**严格 IPv6
翻译前缀**下做 IPv4 ↔ IPv6 编解码：

- **编码（encode）**：把每个裸 IPv4 地址嵌入翻译前缀，得到映射 IPv6 地址；
- **解码（decode）**：把每个裸 IPv6 地址还原为其中嵌入的 IPv4 地址，同时
  校验它确实是该前缀下的**规范映射**。

前缀仅允许 **`/32`、`/40`、`/48`、`/56`、`/64`、`/96`** 六种长度（RFC 6052
§2.2），必须显式带前缀长度且主机位为零。各长度下 IPv4 的 4 个八位组按
**第 64 位边界**安放（RFC 6052 §2.4 表格）：

| 前缀长度 | 嵌入位置（IPv6 字节布局，16 字节） |
| -------- | ---------------------------------- |
| `/32` | 前 4 字节前缀 + IPv4 前 **4** 字节 + `u=00` + IPv4 后 **0** 字节 + 5 字节全零后缀 |
| `/40` | 前 5 字节前缀 + IPv4 前 **3** 字节 + `u=00` + IPv4 后 **1** 字节 + 4 字节全零后缀 |
| `/48` | 前 6 字节前缀 + IPv4 前 **2** 字节 + `u=00` + IPv4 后 **2** 字节 + 3 字节全零后缀 |
| `/56` | 前 7 字节前缀 + IPv4 前 **1** 字节 + `u=00` + IPv4 后 **3** 字节 + 2 字节全零后缀 |
| `/64` | 前 8 字节前缀 + `u=00` + IPv4 全部 **4** 字节 + 1 字节全零后缀 |
| `/96` | 前 12 字节前缀后**直接接 IPv4 4 字节**（无 u 八位、无后缀） |

即除 `/96` 外，IPv4 位都跨过第 64 位边界：边界前安放 `(64 − 前缀长度)/8`
个 IPv4 八位组，随后是恒为零的 **u 八位**（第 8 字节），再放剩余 IPv4
八位组，其余后缀位**全部置零**。

请求体：

| 字段       | 类型       | 说明                                   |
| ---------- | ---------- | -------------------------------------- |
| `prefix`   | `string`   | **必填**，严格 IPv6 CIDR，仅 `/32`、`/40`、`/48`、`/56`、`/64`、`/96`，主机位非零或裸地址返回 422 |
| `encode`   | `string[]` | 待编码的**裸 IPv4 地址**（不接受 IPv6、不接受 CIDR 记法），可省略（默认 `[]`），顺序即返回顺序 |
| `decode`   | `string[]` | 待解码的**裸 IPv6 地址**（不接受 IPv4、不接受 CIDR 记法），可省略（默认 `[]`），顺序即返回顺序；每项必须是前缀下的规范映射 |

示例（服务默认监听 <http://localhost:8000>）：

```bash
curl -s -X POST http://localhost:8000/nat64-codec \
  -H 'Content-Type: application/json' \
  -d '{
        "prefix": "2001:db8::/32",
        "encode": ["192.0.2.33", "198.51.100.7"],
        "decode": ["2001:db8:c000:221::", "2001:db8:c633:6407::"]
      }'
```

响应（`encoded` / `decoded` 分别与 `encode` / `decode` **等长、同序**）：

```json
{
  "encoded": ["2001:db8:c000:221::", "2001:db8:c633:6407::"],
  "decoded": ["192.0.2.33", "198.51.100.7"]
}
```

`/96` 前缀下 IPv4 直接接在前缀后（无 u 八位、无后缀）：

```bash
curl -s -X POST http://localhost:8000/nat64-codec \
  -H 'Content-Type: application/json' \
  -d '{"prefix": "2001:db8:1:2::/96",
       "encode": ["192.0.2.33"],
       "decode": ["2001:db8:1:2::c000:221"]}'
# {"encoded":["2001:db8:1:2::c000:221"],"decoded":["192.0.2.33"]}
```

解码逐项验证以下条件，任一不满足则该地址**不是规范映射**：

1. IPv6 地址落在翻译前缀内（前缀位逐一相等）；
2. 除 `/96` 外，**u 八位（第 8 字节）为零**；
3. 除 `/96` 外，IPv4 位之后的**剩余后缀位全部为零**。

例如 `/32` 下 `2001:db8:c000:221::1` 的最低位后缀非零，整批返回 422：

```bash
curl -i -X POST http://localhost:8000/nat64-codec \
  -H 'Content-Type: application/json' \
  -d '{"prefix": "2001:db8::/32", "decode": ["2001:db8:c000:221::1"]}'
# HTTP/1.1 422 Unprocessable Entity
# {"detail":[{"type":"value_error","loc":["body"],
#   "msg":"Value error, IPv6 address 2001:db8:c000:221::1 under NAT64
#          prefix 2001:db8::/32 has non-zero suffix bits; ...", ...}]}
```

以下输入统一返回 **HTTP 422**：前缀缺失/非法/为 IPv4/主机位非零/前缀长度
不在六种允许值内；`encode` 出现 IPv6 地址、CIDR 记法或非法地址；`decode`
出现 IPv4 地址、CIDR 记法、非法地址或前缀不匹配；`decode` 地址的 u 八位
或后缀非零（非规范映射）。**任一输入非法即整批 422，不返回部分结果**；
空列表（`{"prefix": "2001:db8::/96"}`）合法，返回两个空数组。

### `POST /free-addresses`

运维场景下按序号在一个 CIDR 范围内定位空闲 IP：输入**严格 CIDR 的
`scope`**、占用 CIDR 列表 `occupied`（允许**互相重叠、允许越出 scope**）
以及若干**从 0 开始的十进制序号** `indices`；服务先把占用网段**求并集**、
再**裁剪到 scope**，扣除后得到 scope 内的空闲空间。返回空闲地址**总数
（十进制字符串）**与序号一一对应的地址，地址按**数值升序**定位；全程只做
网段与数量运算，**不逐个枚举地址**，IPv6 `::/0` 也可正常处理。

请求体：

| 字段       | 类型       | 说明                                   |
| ---------- | ---------- | -------------------------------------- |
| `scope`    | `string`   | **必填**，单个严格 CIDR（IPv4 或 IPv6），主机位非零返回 422 |
| `occupied` | `string[]` | 占用 CIDR 列表，可省略（默认 `[]`）。可重叠、重复、包含、越出 scope；先求并集再裁剪；但每条必须与 scope **同地址族**，否则 422 |
| `indices`  | `string[]` | 从 0 开始的十进制序号（**字符串**），可省略（默认 `[]`）。顺序即返回顺序，可重复；不接受负号、前导零（`"01"`）或非数字 |

计数口径与定位规则：

- **所有地址位都计入**：空闲总数包含网络地址与广播地址，如 `/30` 即 4 个
  地址；
- 序号 `0` 对应空闲空间中数值最小的地址，`N-1` 对应最大地址；
- 序号以**十进制字符串**而非 JSON 数字传递——IPv6 空闲空间最多有
  $2^{128}$ 个地址，超出 JSON 安全整数范围（$2^{53}$）；
- `indices` 为空时**仍计算并返回总数**，`addresses` 为空数组。

示例（`occupied` 中 `10.0.0.0/31` 与重复的 `10.0.0.1/32` 先并成
`10.0.0.0/31`，越界的 `9.255.255.252/30` 裁剪掉；空闲只剩 `.2`、`.3`，
序号保持输入顺序且允许重复）：

```bash
curl -s -X POST http://localhost:8000/free-addresses \
  -H 'Content-Type: application/json' \
  -d '{
        "scope": "10.0.0.0/30",
        "occupied": ["10.0.0.0/31", "10.0.0.1/32", "9.255.255.252/30"],
        "indices": ["0", "1", "0"]
      }'
```

响应：

```json
{
  "free_addresses": "2",
  "addresses": ["10.0.0.2", "10.0.0.3", "10.0.0.2"]
}
```

空查询仍返回总数（总数为**十进制字符串**）：

```bash
curl -s -X POST http://localhost:8000/free-addresses \
  -H 'Content-Type: application/json' \
  -d '{"scope": "2001:db8::/120", "occupied": ["2001:db8::/126"]}'
# {"free_addresses":"252","addresses":[]}
```

IPv6 全空间也可处理（`2001:db8::/32` 含 $2^{96}$ 个地址）：

```bash
curl -s -X POST http://localhost:8000/free-addresses \
  -H 'Content-Type: application/json' \
  -d '{"scope": "::/0", "occupied": ["2001:db8::/32"], "indices": ["0"]}'
# {"free_addresses":"340282366841710300949110269838224261120",
#  "addresses":["::"]}
```

序号达到空闲总数（即等于总数或更大）时**整批 422**，不返回部分结果：

```bash
curl -i -X POST http://localhost:8000/free-addresses \
  -H 'Content-Type: application/json' \
  -d '{"scope": "10.0.0.0/31", "indices": ["2"]}'
# HTTP/1.1 422 Unprocessable Entity
# {"detail":[{"type":"value_error","loc":["body"],
#   "msg":"Value error, ordinal 2 is out of range for the free address space
#          (valid range 0..1, 2 free addresses)", ...}]}
```

同样返回 **HTTP 422** 的情形：`scope`/`occupied` 中 CIDR 非法（格式错误、
主机位非零）、`occupied` 与 scope 地址族不一致（IPv4/IPv6 混用）、序号为
非规范十进制（负号、前导零、空串、非数字、JSON 数字类型）。

## 算法说明

1. **解析校验**：`ipaddress.ip_network(value, strict=True)` 严格解析；
2. **族拆分 + 输入折叠**：IPv4、IPv6 独立处理，先对 allow / deny 各自
   `collapse_addresses` 去重、去重叠、去包含；
3. **递归差集**（`app/policy.py::_diff`）：对每个 allow 网络：
   - deny 等于或包含该网络 → 整个删除；
   - deny 与其不相交 → 整段保留；
   - deny 是其严格子网（切穿）→ 拆成左右两个兄弟半区递归处理，
     被整段拒绝的半区丢弃，未触及的半区整体保留；
4. **兄弟合并**：结果再次 `collapse_addresses`，只有完整相邻兄弟前缀
   才能合并回父前缀，从而保证等价性、互不重叠与最少数量；
5. **稳定排序**：按地址族、`network_address.packed`、前缀长度排序。

`/compare` 在同一套判定规则之上另走一条路径（`app/policy.py` 中
`_winner_partition` / `_overlay_partitions` / `_merge_labelled`）：

1. 对每组策略，自 scope 起按前缀树递归：scope 上的获胜条目（最长前缀、
   同长度 deny 优先）作为继承判定，严格子网把当前节点对半切开，判定
   恒定的半区整体保留；
2. 两侧分区叠加求交（任意两个相交的对齐前缀，交集必为较细者），只保留
   `baseline_decision != candidate_decision` 的瓦片；
3. 按转换标签做**带标签的完整兄弟合并**（不动点循环）：同一父网的左右
   两半都在、且转换类型完全相同时才合并，合并后的父网段继续向上合并。

`/audit-rules` 复用同一套**获胜者分区**（`app/policy.py` 中
`audit_rules` / `_winner_partition`）：分区把 scope 切成互不重叠、联合穷尽
scope 的最大 CIDR 瓦片，每块直接携带**获胜条目本体**（无获胜者则为
`unmatched`）。对每条规则：

1. CIDR 与 scope 不相交 → `out_of_scope`（对齐前缀只可能包含或不相交，
   不存在“切穿”）；
2. 否则取与该规则相交的瓦片集合（同样只有相等或包含关系）：
   - 其中存在获胜条目就是本规则的瓦片 → `effective`，witness 取这些瓦片中
     网络地址最小者（瓦片边界地址必在获胜区域内），全程只有网段运算，
     **不枚举地址**；
   - 否则 → `shadowed`，把各瓦片实际获胜条目的 `(side, index)` 去重收集为
     `shadowed_by`；无任何条目获胜的瓦片（`unmatched`）不贡献遮蔽者。

`/minimize-policy` 在获胜者分区之上做**精确最少子集搜索**（`app/policy.py` 中
`minimize_policy` / `_minimize_family`）：

1. 原策略经 `_winner_partition` 把 scope 切成携带获胜条目的最大 CIDR 瓦片。
   获胜者为 `None`（unmatched）的瓦片没有要求：任何覆盖它的规则都会赢得它，
   因此可行解里本来就不会保留覆盖它的规则；
2. 对每个带 side 标签的瓦片，把覆盖它、且与获胜侧同侧的规则作为候选
   （candidate），把覆盖它且匹配键严格更高的**异侧**规则记为该候选的阻挡集合
   （blockers）。同侧规则只会把获胜者换成另一条同判定规则，永远不构成阻挡；
3. 迭代式深度优先分支限界：每轮挑选**未被保证、候选数最少的瓦片**，要么保留其
   一个可行候选（同时强制排除该候选的全部 blockers），要么在已有候选被保留时走
   “只排除、不新增规则”的分支；某候选的 blocker 已被保留即判该候选失效，所有
   候选失效则剪枝回溯。初始上界是“原策略各瓦片获胜者去重后”的可行集合；
4. 状态用 `(retained, excluded)` 位掩码记忆化；规则按 `(side, index)` 规范序编号，
   搜索优先展开编号最小的候选，使规模相当下字典序最小的解尽早成为当前最优，最终
   唯一结果即所有最少解中 `(side, index)` 序列字典序最小者。全程只在 CIDR 瓦片
   与位掩码上运算，**不枚举 IP，也不逐条贪心删除规则**；
5. 确定保留集合后，对**最小方案本身**再做一次获胜者分区：每条保留规则至少赢下
   一个瓦片，其 `witness` 取它所赢瓦片中网络地址最小者。

`/allocate` 的搜索同样建立在 `scope − occupied` 的最小空闲集合之上
（`app/policy.py` 中 `_search` / `_fits` / `_subtract_free`）：

1. 空闲空间表示为排序、互不重叠的最小 CIDR 列表；每次分配用
   `address_exclude` 从包含它的空闲块中扣除，列表性质保持不变；
2. 按申请顺序做**深度优先搜索**：每条申请的候选子网按网络地址**升序**
   枚举，找到的第一个完整方案即为网络地址序列字典序最小者；任一申请
   无候选可放时回溯到上一申请的下一块候选；
3. 每个搜索节点先做**分粒度容量检查**（对每个申请前缀长度 p，比较
   尚未放置的申请折算成 /p 块的需求数与空闲空间可容纳的 /p 块数），
   不可行立即剪枝；失败的 `(深度, 空闲集合)` 状态记入备忘录避免重复
   搜索。

`/anonymize` 是一个 Crypto-PAn 风格的**逐位前缀保持密码**（`app/policy.py`
中 `anonymize` / `_anonymize_address`）：

1. 自最高位向最低位逐位扫描；第 `i` 位的 HMAC-SHA256 消息为
   `地址族标记(0x04/0x06) || 位序 i || 此前 i 个原始位右侧补零到 4/16 字节`，
   密钥为 `key_hex` 解码出的 32 字节；
2. 输出位 = 原始位 XOR 摘要首字节的最高位。补零串只含**原始**位，因此公共
   前缀上每一步输入相同 → 最长公共前缀长度不变；每个前缀节点的 0/1 两个出口
   在同一掩码下仍分别为 0/1（顺序可能整体翻转）→ 全地址族映射为双射；密钥
   固定则结果稳定；
3. CIDR 仅对网络地址做上述变换，随后用原前缀长度重新掩码清零主机位，得到
   规范网段；IPv4、IPv6 用不同族标记做域分离，两类输出各自保持输入顺序。

`/reverse-delegations` 只做确定性的名称拼装（`app/policy.py` 中
`reverse_delegations` / `_parse_reverse_cidr` / `_parse_nameserver`）：

1. 每个条目严格解析为 IPv4 网络（`strict=True` 拒绝主机位），拒绝 IPv6 与
   `/24` 之外的前缀长度，且必须显式带 `/p`；NS 域名按标签规则校验（拒绝
   裸 IP），统一转小写并补单个根点，同批重复目标去重；
2. 整批校验：所有网段必须子网于第一个网段的父 `/24`，按网络地址排序后
   检查相邻对是否相交（排序后相交必发生在相邻对之间），任一不满足整批
   报错；
3. `/24` 直接把 `d.c.b.a.in-addr.arpa.` 作为委派区生成顶点 NS；`/25`～
   `/32` 以「网络地址末段/前缀」为标签在父区下命名 RFC 2317 子区，在父区
   生成子区 NS，并从网络地址起按整数区间枚举覆盖的**全部地址**
   （至多 128 个，含网段与广播地址——二者同样可以有 PTR），逐地址生成从
   父区原名 `n.<父区>` 到子区内 PTR 名 `n.<标签>.<父区>` 的 CNAME；
4. 输出的区与记录按来源网段的 `(network_address.packed, prefixlen)`
   排序，同一网段的 NS 先于 CNAME，每条输出都回带其输入 `cidr`。

`/roa-coverage` 是一个**由 ROA 边界驱动的前缀树分区**（`app/policy.py` 中
`roa_coverage` / `_roa_partition_node` / `_merge_status_pieces`）：

1. scope 与每条 ROA 都严格解析（`strict=True`）；跨地址族、
   `max_length < ROA 前缀长度` 或 `max_length` 超过地址族上限即报错；
   与 scope 不相交的 ROA 被忽略，**比候选粒度 `/L` 更细**的 ROA
   （`prefixlen > L`）落在单个候选内部、不可能覆盖整条候选路由，直接剔除；
2. 自 scope 起把 ROA 分成「已覆盖当前节点（前缀等于或宽于节点）」的
   `active` 与「严格在节点内部」的 `pending` 两组，递归对半切分。节点一旦
   判定为以下情形即整体成块、不再下钻：
   - `active` 中已有「同 ASN 且 `max_length ≥ L`」的授权 ROA → **valid**
     （valid 不会被更深的 ROA 降级）；
   - 已到达 `/L` 边界 → 块内所有对齐候选共享同一状态（有覆盖即 invalid，
     否则 unknown）；
   - 节点已被覆盖但无授权，且 `pending` 中再无可能授权的 ROA → **invalid**
     （错误 ASN、`max_length` 不足的 ROA 只会继续保持 invalid）；
   - 无覆盖且无 `pending` → **unknown**；
3. 只有节点状态仍可能被更深 ROA 改变时才拆成左右兄弟，ROA 按所属半区下传
   （等于半区者转为该半区的 active，严格子网者继续 pending）；因此切分次数
   只与 ROA 边界数相关（节点数上界约为 $O(|ROA| \\cdot \\text{地址宽度})$），
   **从不枚举 `/L` 候选**——`::/0` + `/128` 也只产生少量节点；
4. 叶子块按状态做**带 scope 上限的完整兄弟合并**（不动点循环）：同一父网的
   两半都在、状态相同、且合并结果不超出 scope 时才上提为父网；合并到 scope
   本身即停止，最终得到按网络地址排序、互不重叠、联合穷尽 scope 的
   **最小 CIDR 状态分区**（可短于拟发布长度 `/L`）。核心实现另有基于逐候选
   暴力判定（RFC 6483）的 IPv4/IPv6 随机对拍测试校验分区的正确性与最小性。

`/as-relationship-repair` 在无向 AS 关系图上做**有限域穷举 + 最少改动搜索**
（`app/policy.py` 中 `as_relationship_repair` / `_path_is_valley_free` /
`_hop_kind`）：

1. 每条路径用到的无向关系按规范化 AS 对 `(lo, hi)` 排序；每个被用到的关系
   有 3 种取值：客户为 `lo` 的客户-提供商、客户为 `hi` 的客户-提供商、对等。
   任一路径未用到的关系对合规性无影响，不参与搜索、也不会被改动；
2. 无谷判定是一个三态自动机：状态按「只走过上行」「已走过唯一一次对等」
   「已走过下行」推进；上行只允许出现在对等/下行之前，对等至多一次，否则
   该路径违规；
3. 至多 9 条被用到的关系共 $3^9 = 19683$ 种取值，全部穷举，逐一检查是否让
   **所有**路径同时合规，统计与原关系不同的条数，保留改动最少者；取值组合
   按 AS 对顺序以字典序枚举，因此同分时第一个遇到的方案就是「新关系序列
   字典序最小」的唯一方案，无需二次比较；
4. 不存在任何合规取值时返回 `None`（端点映射为 HTTP 409）。核心实现另有
   独立 $3^n$ 暴力参考实现的随机对拍测试，校验最少改动数、同分方案、违规
   下标与 409 判定。

`/nat64-codec` 完全基于字节布局运算（`app/policy.py` 中
`nat64_codec` / `parse_nat64_prefix` / `_nat64_encode` / `_nat64_decode`）：

1. 前缀严格解析为 IPv6 网络（`strict=True`，拒绝主机位与裸地址），并校验
   前缀长度属于 `/32`、`/40`、`/48`、`/56`、`/64`、`/96`；
2. 编码：以前缀网络地址的 16 字节为底，`/96` 时把 IPv4 四字节直接写入
   字节 12–15；其余长度按 `leading = (64 − 前缀长度) / 8` 把前
   `leading` 个 IPv4 八位组写到前缀之后（仍在第 64 位之前），第 8 字节
   u 八位置零，再把剩余 `4 − leading` 个八位组写到字节 9 起，尾部后缀
   全部清零；
3. 解码：先逐字节比对前缀位，再按同一布局从边界前后拼回 4 个 IPv4 八位组；
   除 `/96` 外同时校验第 8 字节 u 八位为零、IPv4 位之后的后缀字节全部
   为零，任一不符即报错（端点映射为 422，整批拒绝）。核心实现含六种前缀
   长度对照 RFC 6052 §2.4 样例的单测、随机 IPv4 往返对拍及 u 八位/后缀
   非零、前缀不匹配、地址族错误的拒绝用例。

`/free-addresses` 建立在与 `/allocate` 相同的 scope−occupied 最小空闲
集合之上（`app/policy.py` 中 `free_addresses` / `_free_address_blocks`
/ `_resolve_ordinals`）：

1. scope 与每条占用 CIDR 都严格解析（`strict=True`），任一与 scope 不同
   地址族即整批报错；与 scope 不相交的同族占用条目直接忽略；
2. 占用网段先经 `collapse_addresses` **求并集**（重叠、重复、包含自动
   折叠），再由 `scope − 并集` 的递归前缀差集**裁剪到 scope 内**——比
   scope 更宽的占用网段只移除其与 scope 的交集；空闲结果是排序、互不
   重叠的最小 CIDR 列表，**所有地址位**（网络/广播地址）均计入
   `num_addresses` 之和；
3. 定位序号时把所有序号排序后与空闲块列表做一次**顺序归并**：维护当前块
   起始的累计地址数 `base`，序号落在某块内时地址即
   `块网络地址 + (序号 − base)`，**从不枚举块内地址**；重复序号解析到同一
   地址，结果按原始输入顺序回填；
4. 任一号 `≥ 空闲总数` 即报错（端点映射为 422，整批拒绝）；空序号列表
   跳过定位，仅返回总数。IPv6 `::/0` 的总数为 $2^{128}$、扣除 `::/0` 后
   为 0，均由任意精度整数直接算出。核心实现另含 IPv4/IPv6 小范围逐地址
   暴力枚举参考实现的随机对拍测试，校验总数与每个序号的映射。

## 本地开发（不使用 Docker）

需要 Python 3.11+：

```bash
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

运行测试（仅核心测试依赖标准库；API 测试需安装 fastapi、httpx、pytest）：

```bash
pip install -r requirements.txt pytest httpx
pytest -q
```

测试包含与 `ipaddress.address_exclude` 参考实现对拍的 IPv4/IPv6 随机性质
用例，验证结果的等价性与最小性。

## 项目结构

```
.
├── app/
│   ├── main.py        # FastAPI 应用：GET /health、POST /normalize、/evaluate、/compare、/audit-rules、/minimize-policy、/allocate、/anonymize、/reverse-delegations、/roa-coverage、/as-relationship-repair、/nat64-codec、/free-addresses
│   ├── policy.py      # 解析、递归拆分、兄弟合并、统计、最长前缀匹配、获胜者分区、规则审计、分区对比、最少规则子集搜索、子网分配搜索、前缀保持 HMAC 脱敏、反向 DNS 委派计划、ROA 覆盖状态前缀树分区、AS 关系无谷路径最少改动修复、RFC 6052 NAT64 编解码、空闲地址总数统计与序号定位（仅 ipaddress + hmac/hashlib）
│   └── schemas.py     # Pydantic 请求/响应模型与 422 校验
├── tests/
│   ├── test_policy.py # 核心算法单测 + 随机对拍（含 /compare、/audit-rules 逐地址对拍、/minimize-policy 子集暴力枚举对拍、/allocate 暴力枚举对拍、/anonymize 双射/最长公共前缀保持性质与独立参考实现对拍、/reverse-delegations 名称拼装与整批校验、/roa-coverage 逐候选 RFC 6483 暴力对拍与 IPv6 超大范围不枚举性质、/as-relationship-repair 与独立 3^n 暴力参考实现对拍及 409 见证、/nat64-codec RFC 6052 六种前缀长度样例与随机往返对拍、/free-addresses IPv4/IPv6 小范围逐地址暴力枚举对拍与 ::/0 边界）
│   └── test_api.py    # API 层测试（422、409、统计、空请求等，含 /reverse-delegations 排序/CNAME 覆盖/422 路径、/roa-coverage 三态分区/越界与跨族拒绝、/as-relationship-repair 共用修正/字典序决胜/422/409/OpenAPI 文档、/nat64-codec 六长度往返/顺序保持/u 八位与后缀非规范 422/OpenAPI 文档、/free-addresses 重叠并集/越界裁剪/序号越界/族不一致 422/OpenAPI 文档）
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```
