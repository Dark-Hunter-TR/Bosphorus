# Bosphorus

[![build](https://github.com/Dark-Hunter-TR/Bosphorus/actions/workflows/build.yml/badge.svg)](https://github.com/Dark-Hunter-TR/Bosphorus/actions/workflows/build.yml)

**一款面向 Windows 的自学习 DPI(深度包检测)绕过引擎。**
Bosphorus 监视你的出站 HTTPS 连接,自动找出在*你所在网络*上能绕过审查系统的
数据包技巧(针对*每个*站点),锁定该技巧并按网络记忆下来——完全不需要手动
调整。

**Languages:** [English](README.md) · [Türkçe](README.tr.md) · [Русский](README.ru.md) · **中文** · [فارسی](README.fa.md)

> ⚠️ **法律声明。** Bosphorus 是一款网络研究与审查规避工具。请仅在你有权测试
> 的网络和流量上使用它。遵守适用于你的法律法规是你自己的责任。

---

## 目录

- [Bosphorus 是什么](#bosphorus-是什么)
- [简要工作原理](#简要工作原理)
- [详细工作原理](#详细工作原理)
  - [捕获路径](#捕获路径)
  - [连接跟踪与判定](#连接跟踪与判定)
  - [发现生命周期](#发现生命周期)
  - [按网络记忆(NetKey)](#按网络记忆netkey)
  - [ISP 种子池](#isp-种子池--isp-name可选)
  - [实时网络切换](#实时网络切换)
- [规避工具箱](#规避工具箱)
- [发现网格](#发现网格)
- [项目结构](#项目结构)
- [环境要求](#环境要求)
- [从源码构建](#从源码构建)
- [命令行用法](#命令行用法)
- [作为 Windows 服务运行](#作为-windows-服务运行)
- [文件、文件夹与日志](#文件文件夹与日志)
- [安全性与设计决策](#安全性与设计决策)
- [限制与不在范围内的内容](#限制与不在范围内的内容)
- [致谢与来源](#致谢与来源)
- [许可证](#许可证)

## Bosphorus 是什么

许多网络运行着一种中间盒(middlebox),它会检查 TLS `ClientHello` 中以明文
传输的 **SNI**(服务器名称),并丢弃或重置连向被封锁主机的连接。像
**GoodbyeDPI** 和 **zapret** 这样的工具通过拆分、重新排序或遮蔽这个首包来
应对——让中间盒永远看不到干净的 SNI,而真正的服务器却能看到——但它们指望
*你自己*选择一种策略,并寄希望于它恰好能对付你所在 ISP 的审查系统。

Bosphorus 免去了这一步。它自动观察、学习并记忆——见下方的
[工作原理](#简要工作原理)。

它以 Rust workspace 的形式发布:一个可移植的核心引擎、一个轻量的
WinDivert 封装,以及一个还能把自己安装为 Windows 服务的 CLI。

## 简要工作原理

1. **观察。** HTTPS 连接的第一个数据包——也就是以明文携带站点名称的
   `ClientHello`——会原样放行,同时 Bosphorus 观察返回的内容。
2. **检测。** 正常的响应意味着该站点没有被封锁,不会发生任何其他动作。重置
   或静默则将该站点标记为被封锁。
3. **搜索。** 对于被封锁的站点,Bosphorus 会自动尝试约 166 种数据包技巧的
   列表——拆分握手包、发送诱饵包、在数据包 TTL 上做文章。它从不主动打开自己
   的测试连接:只利用你的浏览器或应用本就会发起的重试。
4. **锁定。** 对该站点连续两次证明有效的第一个技巧会被保存下来,并用于此后
   与该站点的所有连接。
5. **记忆。** 学到的技巧会被写入一个与当前网络绑定的小文件。之后重新连上那
   个 Wi-Fi 时,这些设置早已就绪——不需要从头再学一遍。

本节其余部分深入介绍机制;如果你只想看技巧列表,可直接跳到
[规避工具箱](#规避工具箱)。

## 详细工作原理

每个数据包——无论入站还是出站——都会经过一个 WinDivert 句柄和三个内部阶段:

- **conntrack** 把某一连接的原始数据包转换为一个判定:握手是成功、被重置,
  还是超时?
- **discovery** 利用该判定,从网格中为这个特定站点选取下一个候选策略,或者
  锁定一个已经证明有效的策略。
- **transforms** 把选定的策略转换为实际发送出去的数据包批次,用来替代(或
  伴随)原始数据包。

discovery 学到的一切都会定期写入一个与当前网络绑定的小型 JSON 文件(见
[NetKey](#按网络记忆netkey))。

### 捕获路径

一个位于 `NETWORK` 层的单一 WinDivert 句柄,捕获一个刻意收窄的流量切片
(过滤片段逐字取自 GoodbyeDPI):

- **出站**发往 443 端口、看起来像请求或 TLS 握手的 TCP 流量(负载小于
  1200 字节,或以 `GET `/`POST` 开头,或带有 TLS 记录头)。
- **入站**来自 443 端口、携带判定信号的流量:`SYN`+`ACK`(其 TTL 能告诉我们
  服务器的协议栈和跳数)、`RST`,或以 `0x16` 开头的首个数据段
  (`ServerHello`)。
- 环回地址以及私有/链路本地地址范围在两侧都被排除。

机器上的其他一切都不受影响。非 IP、非 TCP 的数据包直接通过。逐包处理循环
运行在 `catch_unwind` 内部,因此单个畸形数据包只会产生一行日志,而不会导致
进程崩溃。

### 连接跟踪与判定

每个被捕获的数据包都会更新每条连接自己的状态机。一旦结果明确,该连接就会被
分类:

| 判定 | 含义 |
|---|---|
| `Success` | 握手成功**且保持住了**——要么有真实数据流动,要么经过一小段宽限窗口而没有被拆除。 |
| `DpiReset` | 在我们的 `ClientHello` 之后、任何 `ServerHello` 之前,服务器方向传来了 `RST`——典型的路径内重置。 |
| `LateReset` | `ServerHello` 通过了,但随后在宽限窗口内一次重置拆除了连接——一种"延迟重置"型审查。计为失败。 |
| `Blackhole` | 发出了 `ClientHello`,但完全没有任何响应。 |
| `TlsError` | 一次并非纯粹 DPI 重置的建连失败。 |
| `Inconclusive` | 在连接超时老化之前没有发生任何决定性事件。 |

`Success` 被故意延迟一小段(约 1 秒)的宽限窗口,这样一个放行 `ServerHello`
*之后*再重置连接的审查系统会被判为 `LateReset`,而不是过早地被记为成功。
真实的入站数据会立即中断这一等待。

### 发现生命周期

discovery **按每个目标**跟踪状态——目标即 `ClientHello` 中经过小写化处理的
站点名称(SNI)。没有可读站点名称的握手(已经被分片,或使用了 Encrypted
Client Hello)永远不会被触碰,也永远不会成为目标。

一个目标要经历四个阶段:

1. **Probe(探测)**——与新站点的第一次连接原样通过,以确定它是否真的被
   封锁。成功则把它移入 **Active**,不需要任何策略。`DpiReset` 或
   `Blackhole` 则把它移入 **Discover**。
2. **Discover(发现)**——网格被逐个候选地扫描。指向同一站点的并发连接会
   并行拿到*不同的*、尚未尝试过的候选,因此扫描速度可以跟上应用本身重试的
   速度。一旦*某一个*特定候选连续取得了两次自己的成功(并行连接中另一个候选
   成功一次不计入此计数),它就会被提升,目标转入 **Active**。
3. **Active(活跃)**——被提升的策略(对于从未被封锁的站点,则是普通直通)
   会用于每一次连接。连续三次失败会把它降回 **Discover**,扫描重新开始。
4. **Exhausted(耗尽)**——所有候选都试过了,没有一个有效。如果之后的构建
   带来了更大的网格,一个耗尽的目标会自动复活进入 **Discover**,只尝试新增
   的候选——旧的尝试不会重复。

一些让扫描更实用的细节:

- **短暂性失败会被原谅一次。** `DpiReset`(一次刻意的重置)会立即排除某个
  候选,但 `Blackhole`——可能只是瞬时丢包——在被排除前会再获得一次机会。
- **感知重传。** 一旦某个策略已经为某条连接发送过,同一 `ClientHello` 之后
  的重传会被原样转发,因此它永远不会被二次去同步(那只会让它进一步损坏)。
- **有界内存。** 空闲、从未被封锁的目标会在 24 小时后被丢弃,任何目标都会
  在 7 天后被丢弃,并且强制执行 4096 个被跟踪目标的硬性上限,优先淘汰价值
  最低的——因此一个运行数周的服务不会为曾经联系过的每一个站点都增长一条
  记录。

### 按网络记忆(NetKey)

学到的状态以每个网络一个 JSON 文件的形式保存。**NetKey** 是网关地址、子网
和 DNS 后缀的哈希值,这样设计是为了让一个仅仅在你的适配器列表中排在最前面
的 VPN 或虚拟适配器,不会产生错误的键。

- 只保存值得重新学习的目标:正在进行的扫描、已提升的策略,或已耗尽的目标。
  从未被封锁的站点重新建立起来毫无成本,因此根本不会被写入。
- 如果网格在不同构建之间发生变化(候选被新增或重新排序),陈旧的条目会
  优雅地降级——Bosphorus 会保留它能保留的部分(比如已学到的 TTL),而不是
  信任被重新编号的 ID。
- **一个网络的文件永远不会被删除或与另一个合并。** 数月间在家、办公室和手机
  热点之间漫游,每个网络都会精确保留它自己学到的内容,不受其他网络影响。

### ISP 种子池(`--isp NAME`,可选)

NetKey 记忆是按*网络*划分的。`--isp NAME` 在此之上增加了一个可选层:它把在
你用同一名称标记的每个网络上都奏效过的策略汇集起来,在未经尝试的网格之前,
谨慎地把它们提供给带有同一标签的**新**网络。

- **派生而非权威。** 池文件是从你各个网络的档案重建出来的;删除它只意味着
  冷启动,不会真正丢失任何已学到的状态。
- **最弱的种子层级。** 与同网络内的提示不同,来自 ISP 池的候选不会跳过初始
  探测,并且仍需要通常的两次成功阈值才能被提升。
- **需要相互印证。** 一个策略只有在该标签下**至少两个不同网络**上证明过
  自己、且总体成功率健康时,才会被提供出来。
- 这个标签叫什么完全由你决定——Bosphorus 从不自行推断你的 ISP。"叫错"顶多
  只会浪费一次尝试的代价。

### 实时网络切换

漫游 Wi-Fi、切换 VPN,或续租 DHCP,都会触发一次重新检查。经过短暂的防抖
之后,Bosphorus 会重新计算 NetKey;如果它变了,旧网络学到的状态会被刷入
它自己的文件,新网络的文件(如果存在)会被加载,过期的连接状态会被清除——
期间不需要重启,也不会丢失任何流量。

## 规避工具箱

**策略**是应用于一个 `ClientHello` 的配方。它由以下几个部件组成,由发现
网格进行混合搭配:

**诱饵包(decoy)**——与真实数据包一起发送的额外数据包,会被中间盒接受,
但会被真正的服务器丢弃:

| 方法 | 作用 |
|---|---|
| `WrongSeq` | 序列号被移到过去的诱饵包。 |
| `WrongChecksum` | 带有刻意损坏的 TCP 校验和的诱饵包。 |
| `TtlLimited` | 带有低 TTL 的诱饵包,使其在到达真实服务器之前就过期。 |
| `SeqPlusTtl` | `WrongSeq` 与低 TTL 组合。 |
| `ChecksumPlusTtl` | `WrongChecksum` 与低 TTL 组合。 |
| `OverlapDisorder` | 没有单独的诱饵包:真实握手被拆分并乱序发送,后半部分前面加上垃圾字节,只有"以最后收到者为准"的服务器才会丢弃它。仅在显式开启时使用。 |

**分片**——在一个或多个位置拆分 TCP 负载:在固定字节偏移处、紧跟在 TLS
记录头之后、紧邻站点名称之前,或站点名称中间。在多于一个位置拆分会产生
两段以上的片段;这些片段可以选择以相反顺序发送。

**诱饵负载**——GoodbyeDPI 逐字节复制的静态 `ClientHello`,或者进一步填充
以把中间盒的重组缓冲区推过其极限的"激进"变体。

**诱饵包的 TTL 策略。** Bosphorus 可以使用你手动固定的值;一个基于真实
服务器实测跳数的粗略自动猜测;或者,一旦确实观测到某个特定站点发来的
DPI 重置,则使用直接从该重置包自身 TTL 读出的、通往发出该重置的设备的
*精确测量*距离——就像服务器跳数是从其 `SYN`+`ACK` 中读出的一样。这个测量
值会自动取代粗略猜测,无需任何配置,并且只针对测量它所依据的那个站点
生效。

**TLS 填充**——在分片之前添加到 `ClientHello` 的 RFC 7685 填充扩展,使
记录长度超过 DPI 重组逻辑分配的任何固定缓冲区。

**发送顺序与重复**——先诱饵后真实,或先真实后诱饵;可选择让诱饵包发送
不止一次。

**服务器协议栈感知。** `OverlapDisorder` 只对保留所收到重叠数据中*最后*
一份副本的服务器有效。Bosphorus 从其 `SYN`+`ACK` 的 TTL 中读出服务器的
协议栈,绝不会把重叠类候选交给 Windows 风格、以先收到者为准的服务器。

## 发现网格

默认网格包含 **166 种策略**,排列顺序使得往往更常奏效的招数最先被尝试:

| 系列 | 数量 | 构成方式 |
|---|---|---|
| 单点拆分 + 诱饵 | 142 | 7 个拆分点 × {正序, 逆序} × 6 种诱饵类型 × {1, 2} 次重复,去重后。 |
| 多段原生拆分 | 12 | 3 种精选切割模式 × {正序, 逆序} × {无诱饵, 错误序列号诱饵}。 |
| RFC 7685 填充 | 6 | 3 个拆分点 × {错误序列号, 错误校验和} 诱饵,512 字节填充。 |
| "激进"诱饵 | 6 | 更大的填充诱饵 × 3 个拆分点 × {错误序列号, 错误校验和}。 |
| 重叠/乱序 | +8 | 仅在显式开启(`--enable-overlap`)时 → 共计 174。4 个拆分点 × 2 种重叠大小。 |

运行 `bosphorus --engine --strategy list` 可以打印出你所构建版本自带的
确切网格。

## 项目结构

一个包含三个 crate 的 Cargo workspace:

| Crate | 角色 |
|---|---|
| `bosphorus-core` | 引擎本体:数据包解析、连接跟踪、策略模型、网格生成器、发现调度器、按网络的持久化。与平台无关——不依赖 WinDivert 或 Windows API。 |
| `bosphorus-divert` | 一个轻量、零分配的 WinDivert 2.2 安全封装。 |
| `bosphorus-cli` | `bosphorus` 可执行文件。把 WinDivert 后端接入核心引擎,并加入 Windows 服务宿主、网络键计算、路由变化监听、日志记录,以及 CLI 已翻译的消息目录。 |

## 环境要求

- **Windows x64。**
- 任何会打开 WinDivert 驱动的操作都需要**管理员权限**
  (`--engine`、`--selftest`、`--passthru`、`--observe`、`service install`)。
  `--check-filters`、`--discovery-demo`、`--mem-bench` 和 `service status`
  不需要提权。
- **WinDivert 2.2.2 驱动必须能够加载。** HVCI/内存完整性、Smart App
  Control,或 WDAC 策略可能会在启动时悄无声息地阻止一个在它们看来"未签名"
  的驱动。`service install` 在注册服务前会检查驱动是否能加载,如果不能则
  拒绝(或在带 `--force` 时给出警告)。
- **稳定的安装路径。** WinDivert 会从 `bosphorus.exe` 所在位置注册其驱动;
  之后移动该可执行文件会同时破坏服务和驱动。请把它放在一个永久位置,或使用
  `service install --install-dir`。
- 若要从源码构建,需要面向 `x86_64-pc-windows-msvc` 目标的
  **Rust(稳定版,1.80 或更新)**。

## 从源码构建

> **手头没有 Windows 机器?** 每次向 `main` 推送、每个 pull request,以及
> 每次手动运行 [`build`](../../actions/workflows/build.yml) workflow,都会在
> GitHub 托管的 Windows runner 上编译 `bosphorus.exe`,并把它——连同
> `WinDivert.dll` 和 `WinDivert64.sys`——作为可下载的 workflow 产物上传。打开
> 最新一次绿色运行的 **Summary** 页面,在 **Artifacts** 下获取
> `bosphorus-windows-x64`。推送 `v*` 标签还会将这些文件作为永久性 GitHub
> Release 发布。不需要本地 Rust 工具链,也不需要下载 WinDivert。

1. **获取 WinDivert 2.2.2 二进制文件。** 从 `basil00/WinDivert` 的
   v2.2.2 release 下载官方的 `WinDivert-2.2.2-A.zip`,并解压使以下路径
   存在:

   ```
   assets/WinDivert-2.2.2-A/x64/WinDivert.dll
   assets/WinDivert-2.2.2-A/x64/WinDivert64.sys
   assets/WinDivert-2.2.2-A/x64/WinDivert.lib
   ```

   `assets/` 已被 git 忽略。`.cargo/config.toml` 已经把 `WINDIVERT_PATH`
   指向了这个文件夹,以相对于 workspace 根目录的路径表示;如果你的 Cargo
   版本较旧、处理相对路径有问题,请改成绝对路径。

2. **构建。**

   ```powershell
   cargo build --release                 # 日常使用的优化构建
   cargo build --profile release-dist    # 发布产物:完整 LTO,已去除符号
   ```

3. **测试。**

   ```powershell
   cargo test                            # 单元与集成测试,不需要提权
   ```

## 命令行用法

```
bosphorus <command> [options]
```

**`--engine [--secs N] [--strategy S] [--enable-overlap] [--profile-dir DIR] [--isp NAME]`**
*需要管理员权限。* 运行引擎。不带 `--strategy` 时,这是完整的自动发现
模式,带有按网络持久化和实时网络切换处理。带 `--strategy` 时,则强制使用
一个固定策略(不与任何网络绑定,也不会被保存)。`--secs N` 会在 N 秒后
自动停止——否则用 `Ctrl+C` 停止。`--profile-dir` 覆盖档案的读写位置。
`--isp NAME` 启用 [ISP 种子池](#isp-种子池--isp-name可选)。

**`--check-filters`**
*不需要提权。* 构建 WinDivert 过滤字符串并检查其语法。

**`--discovery-demo [--fresh]`**
*不需要提权。* 一个不需要驱动的演示,用来证明发现循环能够运行,并且其
进度能在进程重启后保留。`--fresh` 会先清空演示档案。

**`--mem-bench [N]`**
*不需要提权。* 用 `N` 个合成目标(默认 2000)驱动引擎,并打印其内存
占用。

**`--observe [--secs N]`**
*需要管理员权限。* 仅分析——嗅探所有 TCP 和 UDP 流量,不做任何改动,并
打印按目标汇总的表格。适合用来查看某个应用实际连接到了哪里。

**`--passthru [--secs N]`**
*需要管理员权限。* 捕获每一个 `:443` TCP 数据包,记录日志,并原样重新
注入——这是一个冒烟测试,用来证明捕获与重新注入不会破坏网络连接。

**`--selftest`**
*需要管理员权限。* WinDivert 验证测试台:检查新连接处理、`ClientHello`
大小、校验和处理,以及驱动是否能加载。

**`--selftest-m7`**
*需要管理员权限。* 针对重叠/乱序技术的可行性探测。

**`service <install|uninstall|run|status>`**
*是否需要提权取决于子命令*——见
[作为 Windows 服务运行](#作为-windows-服务运行)。

**语言。** 本 README 已被翻译成多种语言,但*程序自身*的消息——即
`--engine` 路径和服务命令上的消息——目前只提供英语和土耳其语版本:默认为
英语,若 Windows 界面语言为土耳其语则为土耳其语。可通过 `--lang en|tr` 或
`BOSPHORUS_LANG` 环境变量强制指定其中任意一种。开发者日志输出和诊断类
子命令始终保持英语。

**日志详细程度。** 设置 `RUST_LOG` 环境变量,例如
`RUST_LOG=bosphorus::discovery=info,bosphorus::strategy=info`。
`bosphorus::mem=debug` 会开启周期性的内存占用摘要。

### `--strategy` 语法

```
--strategy list                       打印默认网格,每行一条
--strategy grid:<i>                    运行网格中编号为 <i> 的条目
--strategy overlap:<seqovl>/<anchor>   强制使用重叠/乱序
--strategy <frag>[/<desync>]           手动构造一个策略
```

- `<frag>` 是一个拆分点、用逗号连接的多段拆分列表,或者 `none`。拆分点可以
  是一个字节偏移量、`sni`、`sni-mid` 或 `tls`。
- `<desync>` 是 `wrongseq`(默认)、`wrongsum`、`ttl:<value>` 或 `none`。
- 在任意形式后追加 `+pad:<n>` 可强制指定 `n` 字节的 TLS 填充。

示例:

```powershell
bosphorus --engine --strategy sni                 # 紧邻站点名称之前拆分
bosphorus --engine --strategy tls,sni             # 三路拆分
bosphorus --engine --strategy 2/wrongsum          # 在第 2 字节处拆分,使用错误校验和诱饵
bosphorus --engine --strategy sni-mid/ttl:6       # 在站点名称中间拆分,TTL 为 6 的诱饵
bosphorus --engine --strategy grid:0              # 网格中的第一条,无论它是什么
```

## 作为 Windows 服务运行

```powershell
# 安装:创建并启动 "Bosphorus" 服务(LocalSystem,自动启动,失败后重启)。
# 会先检查驱动是否能加载。
bosphorus service install [--lang en|tr] [--enable-overlap]
                          [--profile-dir <path>] [--install-dir <path>]
                          [--start auto|demand] [--force]

bosphorus service status                # 不需要提权
bosphorus service uninstall [--purge]   # --purge 同时会删除已保存的数据
bosphorus service run                   # 仅供 SCM 入口使用,不用于交互式场景
```

- `--install-dir` 会把可执行文件和 WinDivert 文件复制到一个稳定的文件夹,
  并从该副本注册服务。
- 安装程序会打印一小段 PowerShell 命令,用来确认服务和驱动确实已经启动——
  值得运行一次,因为启动时的驱动阻止否则会悄无声息地发生。
- 该服务运行的是与不带 `--strategy` 的 `--engine` 相同的自动发现引擎,
  拥有自己独立的按网络档案存储和日志文件夹。生命周期事件还会写入 Windows
  应用程序事件日志,提供者名称为 `Bosphorus`。

## 文件、文件夹与日志

| 路径 | 内容 |
|---|---|
| `assets/WinDivert-2.2.2-A/x64/` | 你在构建时提供的 WinDivert 文件。 |
| `%LOCALAPPDATA%\Bosphorus\profiles\*.json` | 交互式 `--engine` 运行学到的档案,每个网络一个文件。 |
| `%ProgramData%\Bosphorus\profiles\*.json` | 同上,供服务使用(`SYSTEM` 无法使用 `%LOCALAPPDATA%`)。 |
| `%ProgramData%\Bosphorus\logs\` | 服务的滚动日志文件。 |
| 事件查看器 → Windows 日志 → 应用程序,提供者 `Bosphorus` | 服务启动/停止以及驱动故障的痕迹。 |

**使用的是哪个存储?** 如果你传入了 `--profile-dir`,它总是优先生效。
否则,如果服务已安装且已经拥有你当前网络的档案,交互式 `--engine` 运行会
共享服务的存储——这样两者永远不会对同一网络学习两次——否则就退回使用自己
的按用户存储。同时针对同一存储运行服务和一次长时间的交互会话是安全的
(写入是原子的),但它们可能会相互覆盖对方的增量学习成果,因为档案是一个
缓存,而不是永久记录。

从 PowerShell 检查正在运行的实例:

```powershell
Get-Service Bosphorus
Get-WinEvent -ProviderName Bosphorus
Get-ChildItem "$env:ProgramData\Bosphorus\profiles\*.json" | Select Name, LastWriteTime
```

## 安全性与设计决策

- **互联网必须保持可用。** 到任何新站点的第一次连接都会原样放行。非 IP、
  非 TCP 流量永远不会被检查。没有可读站点名称的 `ClientHello` 永远不会被
  修改。`--passthru` 的存在就是为了持续证明捕获与重新注入是透明的。
- **风险最高的技术需要显式开启。** `OverlapDisorder` 可能会在遇到不合适
  类型的服务器时卡住握手,因此自动发现绝不会尝试它,除非你传入了
  `--enable-overlap`——即便如此,它也会被排除在 Windows 风格的服务器之外。
- **干净的关闭至关重要。** 服务的停止处理程序、最终的档案保存,以及驱动
  清理,都运行在 Rust 的 unwind 路径中,这也是发布构建保持 `panic =
  "unwind"` 而非 `"abort"` 的原因。每个数据包也都在 panic 防护内处理,
  因此单个畸形数据包只会降级为一行日志,而不会拖垮进程。
- **第三方字节被明确标注为第三方来源。** WinDivert 过滤片段和静态诱饵
  `ClientHello` 都是从 GoodbyeDPI 逐字节复制而来,并被刻意保持原样。
- **面向长时间运行的有界内存。** 空闲目标会被清除,一个硬性上限限制了
  同时被跟踪的目标数量,周期性摘要让你能在多天运行期间观察内存占用。

## 限制与不在范围内的内容

- **仅支持 Windows**,且仅限 443 端口上的 TLS-over-TCP。普通 HTTP 以及
  其他端口上的 TLS 不被处理。
- **QUIC/HTTP-3** 流量目前会被原样放行——检测过滤器已经存在,但尚未接入
  正在运行的引擎。如果审查系统连 QUIC 也一并封锁某个站点,浏览器在那里
  可能仍会失败,直到它回退到 TCP。
- **DNS** 重定向尚未实现;基于 DNS 的封锁只能被观察到,无法被纠正。
- **IP 层分片**已经过评估并被刻意搁置(黑洞风险过高,在 Windows 上未经
  验证)。
- **Domain fronting** 不在范围内——它需要客户端应用程序的配合,单靠数据包
  操纵无法提供。
- **Encrypted Client Hello (ECH)** 连接不携带任何可读的站点名称,因此
  discovery 没有可以依据的信息;它们会被直接放行。

## 致谢与来源

- **[GoodbyeDPI](https://github.com/ValdikSS/GoodbyeDPI)**(作者
  ValdikSS)——WinDivert 过滤片段和静态诱饵 `ClientHello` 逐字节沿用自
  该项目;诱饵包技术也是以它为模板设计的。
- **[zapret](https://github.com/bol-van/zapret)**(作者
  bol-van)——重叠/乱序技术,以及自动 TTL 启发式算法的形态。
- **[WinDivert](https://github.com/basil00/WinDivert)**(作者
  basil00)——数据包捕获/注入驱动,以其自身许可证单独打包提供。
- `windivert-sys` crate 提供 FFI 绑定。

## 许可证

依你选择,采用 **MIT OR Apache-2.0** 双重许可(如 `Cargo.toml` 中所声明)。
WinDivert 依其自身条款分发——见 `assets/WinDivert-2.2.2-A/LICENSE`。
