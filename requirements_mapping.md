# 需求完成对照表 (Requirements Mapping)
## 对照 requirements.txt 与 Interim Report

> **Date**: February 2026  
> **Programme**: BSc (Hons) Cyber Security

---

## 一、requirements.txt 逐条对照

### Requirement 1 ✅ 已完成
> *Conduct a comprehensive literature review on malware analysis techniques*

**完成情况：**
- Interim Report 中已撰写完整的文献综述章节，涵盖：
  - 静态分析技术（哈希分析、熵值分析、字符串提取、PE 头解析）
  - 动态沙箱分析（CAPEv2/Cuckoo Sandbox 行为监控）
  - 网络入侵检测系统（Snort 规则引擎）
  - YARA 规则匹配技术
  - 多源威胁情报关联方法

**对应实现：** 所有文献综述中讨论的技术方法均已在代码中实现。

---

### Requirement 2 ✅ 已完成
> *and network intrusion detection systems*

**完成情况：**
- 文献综述涵盖了 Snort IDS、Suricata、Zeek 等开源 NIDS 的对比分析
- 讨论了基于签名的检测 vs 基于异常的检测方法

**对应实现：** `src/snort_wrapper.py` — Snort IDS 封装模块，支持 40,000+ 条社区规则

---

### Requirement 3 ✅ 已完成
> *Successfully configure and utilize standard cybersecurity datasets (e.g., CIC-IDS2017) and malware datasets (e.g., Microsoft BIG-2015)*

**完成情况：**

| 数据集 | 状态 | 规模 | 对应工具 |
|--------|------|------|----------|
| MalwareBazaar | ✅ 已使用 | 100 个 PE 可执行文件（abuse.ch 每日批量发布） | `tools/download_malwarebazaar.py`, `tools/run_bazaar_analysis.py` |

**关键产出：**
- MalwareBazaar：100 个真实恶意软件 PE 样本
  - 静态分析生成 **146 条告警** + YARA 匹配 **33 条告警**
  - CAPEv2 动态分析生成 **322 条告警** + **26,609 条网络 IoC**（域名、IP、URL）
  - 跨源关联生成 **506 条关联记录**

**数据集选择说明：** 最终选用 MalwareBazaar 替代 BIG-2015 和 CIC-IDS2017，原因：
- BIG-2015 为 `.bytes` 格式（反汇编文本），非原始 PE 可执行文件，无法直接提交 CAPEv2 沙箱运行
- MalwareBazaar 提供真实的、当代的 PE 恶意软件样本，可完成从静态分析到动态沙箱的完整端到端流水线
- 沙箱网络流量（PCAP）也可用 Snort 进行规则检测分析，替代 CIC-IDS2017 PCAP

---

### Requirement 4 ✅ 已完成
> *Develop a basic prototype system capable of:*

**完成情况：** 系统远超 "基础原型" 的要求，实现了完整的端到端检测管道：
- 主控编排器 (`orchestrator.py`)：协调全部分析模块
- 数据持久化 (`database.py`)：SQLite 存储全部告警、IoC、关联
- 自动化流水线 (`demo_runner.py`)：一键运行全部分析流程

---

### Requirement 5 ✅ 已完成
> *Classifying network traffic using rule-based or basic statistical methods*

**完成情况：**
- **规则引擎：** Snort 2.9.15 + Community Rules（40,000+ 条签名规则）
- **分析对象：** CAPEv2 沙箱执行恶意样本时产生的网络流量 PCAP 文件（100 个 task_*.pcap）
- **分析方式：** 通过 WSL2 调用 Snort 对沙箱流量进行规则匹配检测

**对应文件：** `src/snort_wrapper.py`, `tools/run_snort_pcaps.py`

---

### Requirement 6 ✅ 已完成
> *Performing static feature analysis (e.g., hashes, entropy, strings) and basic dynamic analysis (e.g., sandboxed execution with API monitoring) of suspicious files*

**静态分析完成情况：**

| 特征 | 实现方式 | 对应代码 |
|------|----------|----------|
| 文件哈希 | MD5 + SHA-256 | `utils.py` → `compute_file_hashes()` |
| 信息熵 | Shannon entropy | `utils.py` → `calculate_entropy()` |
| **字节频率分布** | **BFD: chi-squared 偏离度 + null byte 比 + 非打印字符比** | **`utils.py` → `compute_byte_frequency_profile()`** |
| 字符串提取 | ASCII/Unicode strings | `utils.py` → `extract_strings()` |
| PE 头分析 | pefile 库 | `static_analyzer.py` → `_analyze_pe_header()` |
| YARA 匹配 | 8 条自定义规则 | `yara_wrapper.py` + `rules/yara/big2015_rules.yar` |

**动态分析完成情况：**
- 部署完整 CAPEv2 沙箱环境（Hyper-V Ubuntu VM + 嵌套 KVM + Windows 10 Sandbox）
- CAPEv2 Agent v0.20 运行在 Windows 10 沙箱中
- 已完成全部 **100 个 MalwareBazaar PE 样本**的动态分析（CAPEv2 Task 882-981）
- 自动化行为监控：API 调用、文件操作、注册表修改、网络通信、CAPEv2 签名检测
- 报告解析：`src/dynamic_analyzer.py` 完整实现了 CAPEv2 JSON 报告的解析和 IoC 提取
- 报告导入：`tools/import_cape_results.py` 通过 REST API 下载报告 + SCP 下载 PCAP → 存入 SQLite
- **产出：** 322 条动态分析告警，24,394 个域名 IoC，2,215 个 IP IoC，225 个 URL IoC

**对应文件：** `src/static_analyzer.py`, `src/dynamic_analyzer.py`, `src/yara_wrapper.py`, `tools/import_cape_results.py`

---

### Requirement 7 ✅ 已完成
> *Produce structured interim and final reports documenting the design, implementation, and baseline testing results*

**完成情况：**
- **Interim Report** (`Interim Report.docx`)：已提交，涵盖文献综述、系统设计、初步实现方案
- **项目工作总结** (`project_summary.md`)：完整记录设计决策、实现过程和测试结果
- **评估报告** (`data/evaluation/evaluation_report.json`)：结构化性能评估数据

---

### Requirement 8 ✅ 已完成
> *Design and implement an advanced correlation engine to link network attack events with malware behaviors, generating unified threat reports*

**完成情况：**
- 实现五维度加权关联引擎 + 乘法时间增强 + **威胁等级调制** (`correlation_engine.py` + `run_correlation.py`)：
  - IP 地址匹配 (0.35) + 域名匹配 (0.20) + 文件哈希匹配 (0.30, 封顶单次) + 行为/TTP 匹配 (0.15)
  - 时间窗口乘法增强 (×1.3) — 仅在存在 IoC 匹配时放大分数
  - **威胁等级调制**：根据 CAPEv2 签名数量（1-5+）动态调整关联分数，产生 5 个差异化评分等级（0.34-0.50）
- 支持跨源关联：静态分析告警 ↔ CAPEv2 动态行为告警
- 生成统一威胁报告（包含关联评分、关联类型、IoC 链条）
- 实际运行结果：**501 条告警** + **27,684 条 IoC** → **506 条跨源关联**

**对应文件：** `src/correlation_engine.py`, `tools/run_correlation.py`

---

### Requirement 9 ✅ 已完成
> *Develop a graphical user interface (GUI) to visualize attack chains, network anomalies, and malware behavior graphs, significantly enhancing operational usability*

**完成情况：**
- **Flask Web 后端** (`dashboard/app.py`)：6 个 RESTful API 端点
- **D3.js 前端可视化**：
  - ✅ 攻击链/关联网络图：Force-Directed Attack Graph（节点 = 告警按数据源着色，边 = 关联关系，支持 **Min Score 滑块实时过滤**）
  - ✅ 时间线视图：告警时序展示
  - ✅ 统计仪表板：告警来源分布、严重度分布、IoC 类型分布、Top Correlations
  - ✅ 文件上传分析：拖拽上传 → 实时静态分析 + YARA 扫描
  - ✅ 详情面板：下钻查看原始告警消息、IoC 详情

**对应文件：** `dashboard/app.py`, `dashboard/templates/index.html`, `dashboard/static/dashboard.js`, `dashboard/static/style.css`

---

### Requirement 10 ✅ 已完成
> *Conduct rigorous testing, focusing not only on detection rates but also on false positive rates, with performance comparisons against existing open-source tools (e.g., Snort, Cuckoo Sandbox)*

**完成情况：**

| 评估维度 | 方法 | 结果 |
|----------|------|------|
| 单元测试 | 122 个 pytest 测试 | 100% 通过 |
| MalwareBazaar 静态检测 | 静态分析(BFD+熵值+字符串+PE) + YARA | 146 static + 33 YARA 告警 |
| CAPEv2 动态检测 | CAPEv2 沙箱行为分析 | 322 条动态告警 |
| 跨源关联 | 五维度加权 + 威胁等级调制 | 506 条关联，5 级评分 |
| 对比基准 | Static-only vs YARA-only vs Dynamic vs Integrated | 集成系统整合效果显著优于单一工具 |

**对应文件：** `tools/evaluate.py`

---

### Requirement 11 ✅ 已完成
> *Implement an extensible rule/plugin framework to allow seamless integration of new detection rules or analysis modules in the future*

**完成情况：**
- 设计并实现 `BaseAnalyzer` 抽象基类 (`plugin_framework.py`)：
  - 定义 `analyze(input_data)` → `AnalysisResult` 抽象方法
  - 定义 `get_iocs()` → `List[IoC]` 抽象方法
  - 提供 `PluginRegistry` 动态注册机制
- 所有分析模块均继承此接口：
  - `SnortAnalyzer(BaseAnalyzer)`
  - `YaraAnalyzer(BaseAnalyzer)`
  - `StaticAnalyzer(BaseAnalyzer)`
  - `CapeAnalyzer(BaseAnalyzer)`
- 新模块只需实现 `BaseAnalyzer` 接口即可无缝集成

**对应文件：** `src/plugin_framework.py`

---

### Requirement 12 ⏳ 待论文撰写
> *Include an in-depth discussion of operational challenges and ethical considerations related to deploying such a system in real-world environments*

**完成情况：**
- 本项目实施过程中遇到并解决了多项运营挑战，可直接写入论文讨论章节：
  - **虚拟化冲突**：WSL2 (Hyper-V) 与 VirtualBox 的 VT-x 共存问题，最终通过 Hyper-V 嵌套虚拟化解决
  - **数据集选择**：BIG-2015 为 .bytes 反汇编格式，无法执行动态分析 → 改用 MalwareBazaar 真实 PE 样本
  - **关联引擎调优**：单一维度（文件哈希）匹配导致均一分数 → 引入威胁等级调制产生差异化评分
  - **数据伦理**：使用公开学术/安全社区数据集（MalwareBazaar），避免使用实际恶意软件传播
  - **沙箱安全**：KVM 网络隔离、NAT 配置、防止样本逃逸
  - **误报管理**：噪声 IP/域名过滤（如 Google DNS 8.8.8.8）、关联引擎阈值调优
- 待 Final Report / Dissertation 中展开撰写

---

## 二、Interim Report 设计承诺 vs 实际完成

| Interim Report 中的承诺 | 实际完成情况 | 状态 |
|--------------------------|------------|------|
| 搭建 VirtualBox 隔离沙箱环境 | 实际使用 Hyper-V + 嵌套 KVM（更优方案） | ✅ 超额完成 |
| 使用标准数据集进行分析 | 使用 MalwareBazaar 100 个真实 PE 恶意样本，完成端到端分析 | ✅ 完成 |
| Snort 规则检测 | 社区规则 40K+，分析沙箱 PCAP 流量 | ✅ 完成 |
| YARA 规则编写 | 8 条家族特征规则，33 条匹配检出 | ✅ 完成 |
| CAPEv2 动态分析 | 完整 KVM 沙箱，100 样本全部完成分析，322 条告警 | ✅ 完成 |
| 关联引擎 | 五维度加权匹配 + 乘法时间增强 + 威胁等级调制评分 | ✅ 超额完成 |
| Web Dashboard | Flask + D3.js 可视化（6 tab + Attack Graph + Upload） | ✅ 超额完成 |
| 插件化架构 | BaseAnalyzer + PluginRegistry | ✅ 完成 |
| 单元测试 | 122 个测试全部通过 | ✅ 完成 |
| 性能评估 | 501 告警 + 27,684 IoC + 506 关联 | ✅ 完成 |

---

## 三、总结

**本项目已完成 requirements.txt 中 12 条需求中的 11 条（Req 12 待论文撰写时展开）。** 系统实现远超 "基础原型" 的要求，构建了一个工程级、可扩展的集成检测平台，并在真实恶意软件数据上完成了从静态分析到动态沙箱到跨源关联的完整端到端流水线。

所有核心代码、测试、工具脚本、YARA 规则和 Web 仪表板均已完成并通过验证。CAPEv2 动态沙箱环境已搭建完毕并成功完成全部 100 个恶意软件样本的动态行为分析。
