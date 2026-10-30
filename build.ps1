#requires -version 5.1
<#
    构建脚本：用 Windows 自带的 .NET Framework 编译器 csc.exe 编译单文件工具。
    不依赖 Visual Studio，也不需要 .NET SDK。
#>
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$source = Join-Path $root 'src\Patcher.cs'
$dist = Join-Path $root 'dist'
$target = Join-Path $dist 'PCL2下载修复工具.exe'

if (-not (Test-Path $source)) { throw "找不到源码：$source" }

$candidates = @(
    (Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'),
    (Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319\csc.exe')
)
$csc = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $csc) {
    throw '没有找到 .NET Framework 4.x 的 C# 编译器（csc.exe）。请先安装 .NET Framework 4.8。'
}

New-Item -ItemType Directory -Force $dist | Out-Null

# /codepage:65001 必须带上：源文件是 UTF-8，中文提示字符串要靠它正确编译。
& $csc /nologo /target:winexe /codepage:65001 "/out:$target" $source `
    /r:System.dll /r:System.Drawing.dll /r:System.Windows.Forms.dll

if ($LASTEXITCODE -ne 0) { throw "编译失败（csc 退出码 $LASTEXITCODE）" }

$item = Get-Item $target
$hash = (Get-FileHash $target -Algorithm SHA256).Hash.ToLower()

Write-Host ''
Write-Host "已生成：$($item.FullName)"
Write-Host "大小：$($item.Length) 字节"
Write-Host "SHA256：$hash"
