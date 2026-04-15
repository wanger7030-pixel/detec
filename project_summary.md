# An Integrated System for Malware and Network Intrusion Detection and Analysis
## 项目工作总结报告 (Project Work Summary)

> **Date**: February 2026  
> **Programme**: BSc (Hons) Cyber Security

---

## 一、项目概述

本项目设计并实现了一个**集成化恶意软件与网络入侵检测分析系统**，将网络流量分析（Snort IDS）、恶意软件静态分析（YARA + 特征提取）、动态沙箱分析（CAPEv2）三大核心能力整合到统一的检测与关联管道中。系统采用模块化、可插拔架构，配备 Flask + D3.js Web 可视化仪表板，并在真实恶意软件样本（MalwareBazaar 100 个 PE 样本）上完成了全面的端到端分析与跨源关联。

---

## 二、技术栈

| 层级 | 选型 |
|------|------|
| 核心语言 | Python 3.10 |
| 网络入侵检测 | Snort 2.9.15 (WSL2 Ubuntu 22.04) |
| 恶意软件静态分析 | YARA + yara-python + pefile |
| 恶意软件动态分析 | CAPEv2 (Hyper-V Ubuntu VM + KVM 嵌套虚拟化) |
| 数据库 | SQLite3 |
| Web 后端 | Flask |
| Web 前端 | D3.js + 原生 HTML/CSS/JS |
| 测试框架 | pytest |
| 虚拟化 | Hyper-V (嵌套 KVM) |

---

## 三、项目工作流程与里程碑

### Phase 0: 项目基础架构搭建

**工作内容：**
- 设计并创建标准化项目目录结构（`src/`, `tests/`, `tools/`, `dashboard/`, `rules/`, `data/`）
- 实现全局配置管理模块 (`config.py`)：定义路径、分析阈值、权重参数等
- 实现可扩展插件基类 (`plugin_framework.py`)：定义 `BaseAnalyzer` 抽象接口，支持 `analyze()` 和 `get_iocs()` 方法，所有分析模块均继承此接口
- 实现通用工具函数库 (`utils.py`)：文件哈希计算、熵值计算、字节频率分析、字符串提取、安全路径操作等

**成果：** 11 个核心源代码文件，清晰的模块职责分离和依赖关系

---

### Phase 1: 核心检测模块开发

**工作内容：**

#### 静态分析模块 (`static_analyzer.py`)
- 文件哈希计算（MD5, SHA-256）
- Shannon 信息熵计算（用于识别加壳/加密样本）
- **字节频率分布分析 (BFD)**：基于 chi-squared 偏离度的 256-bin byte histogram 分析，检测异常字节分布、高空字节比、高非打印字符比（参考 Saxe & Berlin 2015, Raff et al. 2017）
- 可读字符串提取（ASCII/Unicode）
- PE 文件头信息解析（Section 分析、导入表分析）
- 自动生成结构化告警与 IoC（Indicators of Compromise）

#### Snort 网络流量分析 (`snort_wrapper.py`)
- WSL2 Ubuntu 22.04 环境下 Snort 2.9.15 的安装与配置
- 通过 subprocess 调用 Snort 分析 PCAP 文件
- 社区规则引擎集成（40,000+ 条规则）
- 告警解析器：将 Snort `alert_fast` 输出解析为结构化字典

#### YARA 规则匹配 (`yara_wrapper.py`)
- 基于 yara-python 库的规则加载与文件扫描
- 手工编写 8 条恶意软件家族特征 YARA 规则
- 匹配结果结构化输出（文件哈希、匹配规则名、标签）

#### 动态分析模块 (`dynamic_analyzer.py`)
- CAPEv2 REST API 集成：样本提交、状态查询、报告下载
- JSON 行为报告解析：提取进程创建、文件操作、注册表修改、网络通信、API调用、CAPEv2 签名等行为
- 实现 `CapeAnalyzer` 类，继承 `BaseAnalyzer` 接口

---

### Phase 2: 关联引擎与数据编排

**工作内容：**

#### 关联引擎 (`correlation_engine.py`)
- **五维度加权匹配机制 + 乘法时间增强：**
  - IP 地址精确匹配 (权重 0.35)
  - 域名/URL 子串匹配 (权重 0.20)
  - 文件哈希精确匹配 (权重 0.30) — 封顶为单次命中，防止 MD5+SHA256 双重计分
  - 行为/TTP 匹配 (权重 0.15) — YARA 规则、Snort 分类、CAPEv2 签名名称、恶意软件家族
  - 时间窗口乘法增强 (×1.3) — 仅在存在 IoC 匹配时提升分数
- **威胁等级调制（Threat-Level Modulation）：** 基于 CAPEv2 检测到的签名数量动态调整最终关联分数（0-0.20 奖励），使不同威胁等级的样本产生差异化评分
- 综合评分阈值过滤（默认 > 0.30 标记为关联事件）
- 跨源关联报告生成

#### 数据持久化 (`database.py`)
- SQLite 数据库设计：4 张核心表（alerts, samples, correlations, iocs）
- 完整的 CRUD 操作接口
- 批量插入、去重、查询与统计功能

#### 主控编排器 (`orchestrator.py`)
- 调度所有分析模块的执行
- 收集分析结果 → 关联引擎 → 统一威胁报告
- 支持单文件分析、目录批量分析、PCAP 分析等多种运行模式

---

### Phase 3: Web 可视化仪表板

**工作内容：**

#### Flask 后端 (`dashboard/app.py`)
- 6 个 RESTful API 端点：
  - `GET /api/stats` — 统计概览
  - `GET /api/alerts` — 告警列表（含 IoC 详情）
  - `GET /api/correlations` — 跨源关联结果
  - `GET /api/iocs` — IoC 指标汇总
  - `GET /api/timeline` — D3.js 时间线数据
  - `POST /api/analyze` — 实时文件上传分析

#### D3.js 前端可视化
- 时间线视图 (Timeline)：展示告警时序关系
- 力导向图 (Force-Directed Attack Graph)：节点 = 告警（按数据源着色），边 = 关联关系，支持 Min Score 滑块实时过滤
- 统计仪表板：检测率分布、告警类型饼图、数据源分布、IoC 类型分布
- 文件上传分析：拖拽上传文件，实时显示静态分析 + YARA 扫描结果
- 详情面板：点击下钻查看原始告警消息、IoC 详情

---

### Phase 4: 测试与质量保证

**工作内容：**
- 编写 **122 个单元测试**（pytest），覆盖全部 6 个核心模块
- 全部测试通过 ✅

| 测试文件 | 测试数 | 状态 |
|----------|-------:|------|
| `test_utils.py` | 27 | ✅ Pass |
| `test_plugin_framework.py` | 18 | ✅ Pass |
| `test_static_analyzer.py` | 19 | ✅ Pass |
| `test_database.py` | 22 | ✅ Pass |
| `test_correlation_engine.py` | 18 | ✅ Pass |
| `test_orchestrator.py` | 18 | ✅ Pass |

---

### Phase 5: 合成数据集成演示

**工作内容：**
- 开发测试数据生成器 (`generate_test_data.py`)：生成 18 个样本（6 家族 × 3）
- 开发端到端流水线脚本 (`demo_runner.py`)

**成果：**

| 指标 | 数值 |
|------|-----:|
| 告警数 | 76 |
| IoC 指标数 | 407 |
| 样本数 | 18 |
| 关联数 | 183 |

---

### Phase 6: 真实数据集分析 — MalwareBazaar

#### MalwareBazaar 恶意软件数据集
- **数据来源：** abuse.ch MalwareBazaar 每日批量发布（https://datalake.abuse.ch/malware-bazaar/daily/）
- **样本筛选：** 从每日 ZIP 包中提取 **100 个 PE 格式可执行文件**（MZ 头验证 + 大小过滤 1KB-10MB）
- **数据获取工具：** `tools/download_malwarebazaar.py`
- **无需认证：** 使用公开的每日批量数据源

**静态分析 + YARA 分析（`tools/run_bazaar_analysis.py`）：**

| 指标 | 数值 |
|------|-----:|
| PE 样本数 | 100 |
| 静态分析告警 | 146 |
| YARA 匹配告警 | 33 |
| IoC 指标数 | 1,075 (file_hash_md5 + file_hash_sha256 + 字符串提取) |

---

### Phase 7: CAPEv2 动态沙箱分析

**工作内容：**

这是本项目的重大技术挑战，涉及多层虚拟化架构的搭建：

1. **Hyper-V 方案**
   - 启用 Windows 11 Enterprise 的 Hyper-V 功能
   - 创建 Ubuntu 22.04 Hyper-V VM，启用 `ExposeVirtualizationExtensions`
   - 成功实现嵌套 KVM 虚拟化（16 个 vmx CPU 核心）
   - 全套 CAPEv2 自动化部署：PostgreSQL, MongoDB, Suricata, Yara, Mitmproxy
   - 创建 Windows 10 KVM 沙箱 (4GB RAM, 2 vCPU, 65GB 磁盘)
   - 安装 Python 3.10 x86 + CAPEv2 Agent v0.20
   - 创建 Clean Snapshot 并配置 KVM Machinery

2. **CAPEv2 实际运行**
   - 成功提交全部 **100 个 MalwareBazaar PE 样本**到 CAPEv2 队列（Task 882-981）
   - 分析完成后通过 REST API 下载 JSON 行为报告（100 份）
   - 通过 SCP 下载沙箱网络流量 PCAP 文件（100 个 `task_*.pcap`）
   - 报告导入工具 `tools/import_cape_results.py`：解析 CAPEv2 JSON 报告 → 提取签名、网络行为、IoC → 存入 SQLite
   - 生成 **322 条动态分析告警** + **24,000+ 条网络 IoC**（域名、IP、URL）

**最终架构：**
```
Windows 11 Host (Hyper-V)
  ├── WSL2 Ubuntu 22.04 → Snort 2.9.15 (PCAP 网络流量分析)
  └── Hyper-V Ubuntu VM (CAPEv2 Host)
       ├── CAPEv2 Server (Web UI + 处理器)
       ├── PostgreSQL + MongoDB + Suricata
       ├── KVM (嵌套虚拟化 ✅)
       │    └── Windows 10 沙箱
       │         └── CAPE Agent v0.20
       └── 分析存储 (/opt/CAPEv2/storage/)
```

---

### Phase 8: Snort 沙箱流量分析

**工作内容：**
- 开发 `tools/run_snort_pcaps.py`：自动将 CAPEv2 沙箱产生的 PCAP 文件通过 WSL2 提交给 Snort 分析
- 解析 Snort fast alert 格式输出 → 转换为框架 Alert/IoC 对象 → 存入 SQLite
- 将沙箱网络行为与 Snort 规则引擎检测结果关联

---

### Phase 9: 跨源关联分析

**工作内容：**
- 开发 `tools/run_correlation.py`（v8）：端到端关联流水线
  - 基于文件哈希的跨源 IoC 匹配（静态分析 ↔ 动态分析）
  - 威胁等级调制算法：根据每个样本的 CAPEv2 签名数量调整关联分数
  - 噪声过滤：排除 Google DNS (8.8.8.8) 等公共 IP 的虚假关联

**关联分析结果：**

| 指标 | 数值 |
|------|-----:|
| 有效关联数 | **506** |
| 关联类型 | file_hash（跨源文件哈希匹配） |
| 分数范围 | 0.34 – 0.50 |
| 分数等级 | 5 级（按 CAPEv2 签名数量分层） |

| 分数 | 数量 | 含义 |
|------|-----:|------|
| 0.50 | 20 | 高威胁（5+ CAPEv2 签名） |
| 0.46 | 56 | 中高威胁 |
| 0.42 | 132 | 中等威胁 |
| 0.38 | 236 | 中低威胁 |
| 0.34 | 62 | 低威胁（1 个签名） |

---

## 四、项目文件清单

### 核心源代码 (`src/`)
| 文件 | 功能 |
|------|------|
| `config.py` | 全局配置管理 |
| `plugin_framework.py` | 可扩展插件基类 (BaseAnalyzer) |
| `utils.py` | 工具函数库（含 BFD 分析） |
| `static_analyzer.py` | 静态特征分析（含 BFD 增强） |
| `snort_wrapper.py` | Snort IDS 封装 |
| `yara_wrapper.py` | YARA 规则匹配 |
| `dynamic_analyzer.py` | CAPEv2 动态分析 |
| `correlation_engine.py` | 五维度关联引擎 + 威胁等级调制 |
| `database.py` | SQLite 持久化 |
| `orchestrator.py` | 主控编排器 |

### 测试代码 (`tests/`) — 122 个测试全部通过
### 工具脚本 (`tools/`) — 关键脚本清单：
| 脚本 | 功能 |
|------|------|
| `download_malwarebazaar.py` | MalwareBazaar 每日样本下载 |
| `run_bazaar_analysis.py` | 静态 + YARA 批量分析 |
| `import_cape_results.py` | CAPEv2 报告导入 + PCAP 下载 |
| `run_snort_pcaps.py` | Snort 分析沙箱 PCAP |
| `run_correlation.py` | 跨源关联引擎（v8 威胁等级调制） |
| `evaluate.py` | 综合性能评估 |
| `generate_test_data.py` | 合成测试数据生成 |

### Web 仪表板 (`dashboard/`) — Flask + D3.js
### YARA 规则 (`rules/yara/`) — 8 条家族特征规则

---

## 五、核心成果总结

| 指标 | 数值 |
|------|------|
| 核心代码模块 | 11 个 Python 模块 |
| 单元测试 | 122 个测试，100% 通过 |
| MalwareBazaar 样本数 | 100 个 PE 可执行文件 |
| 总告警数 | **501**（static: 146, dynamic_cape: 322, yara: 33） |
| 总 IoC 数 | **27,684**（domain: 24,394, ip: 2,215, hash: 850, url: 225） |
| 跨源关联数 | **506**（5 级威胁评分 0.34-0.50） |
| CAPEv2 动态分析 | 100 样本完成，KVM 硬件加速运行 |
| Web 仪表板 | 6 个 API 端点 + D3.js 交互式图表（含 Attack Graph 过滤） |
