# PCL2 下载修复工具

> 解除 PCL2 启动器里被停用的「下载 Minecraft 版本」功能。一键修复、一键回退，支持官方版 2.99.0.0 与 2.99.0.1。

![选择界面](docs/picker.png)

修复后，PCL2 的「下载 → 原版游戏」页面恢复正常，可以照常安装原版、Forge、Fabric、OptiFine：

![恢复后的下载页](docs/download-page.png)

---

## 这是什么

从 PCL2 2.99.0.0 开始，官方把「下载 → 原版游戏」里的版本列表加载器换成了一个只弹提示的空任务：

> 为遵守相关法律法规，PCL 暂时不再提供 MC 下载功能，非常抱歉 qwq……

2.99.0.1 更进一步：除了保留上面这个空任务，还在下载页的构造函数里把「原版游戏」「社区资源」两个入口设成了隐藏，默认页改成了「整合包」——所以看起来像是整个下载区域被删掉了。

但程序里其余的下载、安装逻辑（版本列表、json、库文件、资源文件、Forge/Fabric/OptiFine 安装器）其实都还完整保留，只是入口被摘掉了。

本工具在二进制层面把这两处改回去，**只改 IL 字节，文件大小、元数据、方法偏移全部不变**。

> 本工具只恢复客户端里的下载入口，不涉及账号、验证、联机等任何其他行为。

## 功能

- **自动识别**：同目录下改名过的启动器、官方版、社区版、多个候选都能识别
- **一键修复 / 一键回退**：按选中项的状态自动启用按钮
- **回退不需要备份**：解析 .NET 元数据重建原始 IL，与修补前逐字节一致；有备份时优先走备份（更快）
- **双版本支持**：2.99.0.0 与 2.99.0.1 两套结构分别处理
- **不乱动文件**：社区版识别为「无需修复」；结构不认识时直接报错退出，不写文件
- **可脚本化**：`--silent` / `--silent --restore`，结果写入 `fix-log.txt`

## 使用方法

1. 下载发布页的 `PCL2下载修复工具.exe`（或自己编译，见下文）
2. 把它放到 PCL2 所在的文件夹（和启动器 exe 同一目录）
3. 双击运行，选中启动器，点「修复」
4. 打开 PCL2 → 下载 → 原版游戏，版本列表就回来了

想恢复原状就再运行一次，选「回退」。

列表右侧的状态含义：

| 状态 | 含义 |
| --- | --- |
| 待修复 | 存在下载限制，可以修复 |
| 已修复 | 已经打过补丁，可以回退 |
| 无需修复 | 社区版，或本来就没有限制 |

## 命令行

```text
PCL2下载修复工具.exe                     图形界面
PCL2下载修复工具.exe --silent            不弹窗，直接修复第一个找到的启动器
PCL2下载修复工具.exe --silent --restore  不弹窗，直接回退第一个找到的启动器
```

返回码：`0` 完成 · `1` 用户取消 · `2` 无需操作 · `3` 未能完成 · `4` 异常

## 工作原理

### 1. 版本列表加载器

`PCL.PageDownloadInstall.LoaderInit()` 里原本是一段构造空任务的 IL，共 48 字节：

```text
72 <"关闭下载">
7E <缓存委托字段> 2C 07 7E <缓存委托字段> 2B 16
7E <闭包单例字段> FE 06 <lambda 方法>
73 <Action`1::.ctor> 25 80 <缓存委托字段> 14 18 73 <LoaderTask`2::.ctor>
```

工具把它整体替换成调用 PCL 自带的加载器：

```text
7E <ModDownload::DlClientListLoader> 2B 29 00 00 ... （其余 41 字节填 00）
```

`2B 29` 是 `br.s`，跳过后面原本的剩余指令，方法体长度仍然是 94 字节。

### 2. 2.99.0.1 的隐藏入口

`PCL.PageDownloadLeft..ctor()` 中：

```text
02 28 <get_ItemInstall>  18 6F <set_Visibility>    // Collapsed(2)
02 6F <get_LabResource> 18 6F <set_Visibility>    // Collapsed(2)
02 18 7D <PageID 字段>                            // 默认页 = 2（整合包）
02 6F <get_ItemMod> 17 6F <set_Checked>            // 默认选中 = 整合包
```

工具把三处 `0x18`（`ldc.i4.2`，Collapsed）改成 `0x16`（`ldc.i4.0`，Visible），PageID 的 `0x18` 也改成 `0x16`（默认页 = 原版游戏），并把最后一条的 `get_ItemMod` 换成 `get_ItemInstall`，让左侧高亮落在「原版游戏」上。

### 3. 回退为什么不需要备份

补丁替换的那 48 字节里连带抹掉了 5 个 IL 记号，回退时需要把它们算回来：

| 记号 | 恢复方式 |
| --- | --- |
| 缓存委托字段 `$IR3-3` | 解析元数据 TypeDef/Field 表，按名字查找 |
| 闭包单例字段 `$I` | 同上 |
| lambda 方法 `_Lambda$__R3-3` | 解析 MethodDef 表，按名字查找 |
| `Action<T>` 构造函数 | 复用紧随其后、未被改动的 onFinish 指令里的 token |
| `LoaderTask<T1,T2>` 构造函数 | 从 `ModDownload` 的静态构造函数里取出（紧跟 `"DlClientList Main"` 之后） |

2.99.0.1 的可见性/PageID/选中项同样按窗口结构定位后翻回常量。实测两个版本删掉备份后回退，结果与修补前逐字节一致。

## 从源码构建

只需要 Windows 自带的 .NET Framework 4.x 编译器，**不需要 Visual Studio，也不需要 .NET SDK**。

```bat
build.cmd
```

或：

```powershell
powershell -ExecutionPolicy Bypass -File build.ps1
```

产物输出到 `dist\PCL2下载修复工具.exe`，脚本会打印大小与 SHA256。

编译参数固定为：

```text
csc.exe /nologo /target:winexe /codepage:65001
        /r:System.dll /r:System.Drawing.dll /r:System.Windows.Forms.dll
```

`/codepage:65001` 不能省：源码是 UTF-8，中文提示字符串要靠它正确编译。

## 兼容性

| PCL2 版本 | 结构 | 支持情况 |
| --- | --- | --- |
| 2.99.0.0 官方版 | 只有空加载器 | ✅ 修复 / 回退 |
| 2.99.0.1 官方版 | 空加载器 + 入口隐藏 | ✅ 修复 / 回退 |
| 2.15.1.0 社区版 | 本身没有下载限制 | 显示「无需修复」，不动文件 |
| 更早的 2.x | 未测试 | 结构对不上会提示「无法解析」，不改文件 |

已修复文件与原始文件的 SHA256（官方版，可用于核对）：

```text
2.99.0.0  原始  6B6E1260CB5A1D6A303855F1C60CAB3D0BC1AEBBA7E40A964180188B271E7386
2.99.0.0  修复  E0B4D0167ACD6191EE0052624042E01F047C6E65E16089BBB844638A494B8A7C

2.99.0.1  原始  0DB34E19D9EEB6D496D20FABE786EC16BBD36BA6B0CCDC8D29CB7E909C114397
2.99.0.1  修复  F6E6025F434709C2997F4C01F94CAEF2CA743602CD6DB5F01C7F9C0D8ACBEF7A
```

注意：PCL2 自动更新会覆盖 exe，补丁随之失效，更新后重新运行一次工具即可。

## 免责声明

- 本项目与 PCL2 作者无关，是非官方的第三方工具
- 修改二进制文件存在风险，请自行备份启动器；项目本身不附带任何 PCL2 文件
- 仅供学习交流，请遵守当地法律法规以及软件的使用许可

## 许可

[MIT](LICENSE) © 2026 YamIpass

---

## English

**PCL2 Download Unlocker** — a tiny Windows tool that re-enables the removed "Download Minecraft" section in PCL2 (Plain Craft Launcher 2) 2.99.0.0 / 2.99.0.1.

Since 2.99.0.0 the launcher replaces the version-list loader with a stub that only throws "download disabled" notice; 2.99.0.1 additionally hides the download entries in `PageDownloadLeft..ctor`. The tool patches those IL bytes in place (48-byte block → call the built-in `DlClientListLoader`; visibility/PageID constants flipped back), and can restore the original bytes without any backup by rebuilding the erased IL tokens from .NET metadata tables.

Both patched and original outputs are byte-for-byte verified against the upstream binaries. Build with `build.cmd` (only needs the .NET Framework 4.x `csc.exe` shipped with Windows). Licensed under MIT. Not affiliated with the PCL2 authors.
