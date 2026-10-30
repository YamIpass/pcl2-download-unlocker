using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Forms;

namespace PclDownloadFix
{
    internal sealed class PeSection
    {
        public uint VA, VSize, Raw, RawSize;
    }

    internal sealed class PeImage
    {
        public readonly byte[] B;
        private readonly List<PeSection> sections = new List<PeSection>();

        public PeImage(byte[] bytes)
        {
            B = bytes;
            Parse();
        }

        private uint U16(int o) { return BitConverter.ToUInt16(B, o); }
        private uint U32(int o) { return BitConverter.ToUInt32(B, o); }

        public uint TextStart, TextSize;

        private void Parse()
        {
            if (B.Length < 0x100) throw new Exception("文件太小，不是有效的 PE 文件。");
            int pe = BitConverter.ToInt32(B, 0x3C);
            if (pe <= 0 || pe + 24 > B.Length) throw new Exception("PE 头无效。");
            if (U32(pe) != 0x00004550) throw new Exception("不是有效的 PE 文件（缺少 PE 签名）。");
            int numSec = (int)U16(pe + 6);
            int optSize = (int)U16(pe + 20);
            int optStart = pe + 24;
            if (optStart + optSize > B.Length) throw new Exception("PE 可选头无效。");
            for (int i = 0; i < numSec; i++)
            {
                int o = optStart + optSize + i * 40;
                if (o + 40 > B.Length) throw new Exception("节表无效。");
                var s = new PeSection();
                s.VSize = U32(o + 8);
                s.VA = U32(o + 12);
                s.RawSize = U32(o + 16);
                s.Raw = U32(o + 20);
                sections.Add(s);
                string name = Encoding.ASCII.GetString(B, o, 8).TrimEnd('\0');
                if (name == ".text") { TextStart = s.Raw; TextSize = s.RawSize; }
            }
        }

        public uint RvaToOffset(uint rva)
        {
            foreach (var s in sections)
            {
                uint size = Math.Max(s.VSize, s.RawSize);
                if (rva >= s.VA && rva < s.VA + size)
                    return rva - s.VA + s.Raw;
            }
            throw new Exception(string.Format("无法定位 RVA 0x{0:X}。", rva));
        }

        public int MetadataRootOffset()
        {
            int optStart = BitConverter.ToInt32(B, 0x3C) + 24;
            ushort magic = (ushort)U16(optStart);
            int dirStart = optStart + (magic == 0x20B ? 112 : 96);
            int clrDir = dirStart + 14 * 8;
            uint clrRva = U32(clrDir);
            if (clrRva == 0) throw new Exception("该文件不是 .NET 程序。");
            uint clrOff = RvaToOffset(clrRva);
            uint metaRva = U32((int)clrOff + 8);
            if (metaRva == 0) throw new Exception("找不到 .NET 元数据。");
            return (int)RvaToOffset(metaRva);
        }
    }

    internal sealed class UsHeap
    {
        private readonly byte[] heap;
        public UsHeap(byte[] h) { heap = h; }

        public static UsHeap Build(PeImage img)
        {
            int root = img.MetadataRootOffset();
            byte[] b = img.B;
            if (BitConverter.ToUInt32(b, root) != 0x424A5342) throw new Exception("元数据签名无效。");
            int verLen = BitConverter.ToInt32(b, root + 12);
            int p = root + 16 + verLen;
            p = (p + 3) & ~3;
            int streams = BitConverter.ToUInt16(b, p + 2);
            p += 4;
            for (int i = 0; i < streams; i++)
            {
                int off = BitConverter.ToInt32(b, p);
                int size = BitConverter.ToInt32(b, p + 4);
                int nameStart = p + 8;
                int nameEnd = nameStart;
                while (b[nameEnd] != 0) nameEnd++;
                string name = Encoding.ASCII.GetString(b, nameStart, nameEnd - nameStart);
                if (name == "#US")
                {
                    var h = new byte[size];
                    Array.Copy(b, root + off, h, 0, size);
                    return new UsHeap(h);
                }
                int nameLen = nameEnd - nameStart + 1;
                p = nameStart + ((nameLen + 3) & ~3);
            }
            throw new Exception("找不到 #US 字符串堆。");
        }

        public uint FindToken(string text)
        {
            int p = 1;
            while (p < heap.Length)
            {
                int size;
                int len = ReadCompressed(heap, p, out size);
                if (len <= 0) return 0;
                int dataStart = p + size;
                if (dataStart + len > heap.Length) return 0;
                if (len > 1)
                {
                    string s = Encoding.Unicode.GetString(heap, dataStart, len - 1);
                    if (s == text) return 0x70000000u | (uint)p;
                }
                p = dataStart + len;
            }
            return 0;
        }

        public static int ReadCompressed(byte[] b, int pos, out int size)
        {
            byte first = b[pos];
            if ((first & 0x80) == 0) { size = 1; return first; }
            if ((first & 0xC0) == 0x80) { size = 2; return ((first & 0x3F) << 8) | b[pos + 1]; }
            size = 4;
            return ((first & 0x1F) << 24) | (b[pos + 1] << 16) | (b[pos + 2] << 8) | b[pos + 3];
        }
    }

    internal sealed class MetaTables
    {
        private readonly byte[] b;
        private readonly int stringsBase;
        private readonly int[] rowCount = new int[64];
        private readonly int[] rowOff = new int[64];
        private readonly int[] rowLen = new int[64];
        private readonly int strIdxSize, guidIdxSize, blobIdxSize;

        public MetaTables(PeImage img)
        {
            b = img.B;
            int root = img.MetadataRootOffset();
            if (BitConverter.ToUInt32(b, root) != 0x424A5342) throw new Exception("元数据签名无效。");
            int verLen = BitConverter.ToInt32(b, root + 12);
            int p = (root + 16 + verLen + 3) & ~3;
            int streams = BitConverter.ToUInt16(b, p + 2);
            p += 4;
            int tablesOff = -1, stringsOff = -1;
            for (int i = 0; i < streams; i++)
            {
                int off = BitConverter.ToInt32(b, p);
                int nameStart = p + 8;
                int nameEnd = nameStart;
                while (b[nameEnd] != 0) nameEnd++;
                string name = Encoding.ASCII.GetString(b, nameStart, nameEnd - nameStart);
                if (name == "#~" || name == "#-") tablesOff = root + off;
                else if (name == "#Strings") stringsOff = root + off;
                p = nameStart + (((nameEnd - nameStart + 1) + 3) & ~3);
            }
            if (tablesOff < 0) throw new Exception("找不到元数据表流。");
            if (stringsOff < 0) throw new Exception("找不到字符串堆。");
            stringsBase = stringsOff;

            byte heapSizes = b[tablesOff + 6];
            strIdxSize = (heapSizes & 0x01) != 0 ? 4 : 2;
            guidIdxSize = (heapSizes & 0x02) != 0 ? 4 : 2;
            blobIdxSize = (heapSizes & 0x04) != 0 ? 4 : 2;

            ulong valid = BitConverter.ToUInt64(b, tablesOff + 8);
            int q = tablesOff + 24;
            for (int t = 0; t < 64; t++)
            {
                if ((valid & (1UL << t)) == 0) continue;
                rowCount[t] = BitConverter.ToInt32(b, q);
                q += 4;
            }
            for (int t = 0; t < 64; t++) rowLen[t] = RowLength(t);
            int dataOff = q;
            for (int t = 0; t < 64; t++)
            {
                rowOff[t] = dataOff;
                dataOff += rowLen[t] * rowCount[t];
            }
        }

        private int IdxSize(int table)
        {
            return rowCount[table] < 65536 ? 2 : 4;
        }

        private int CodedSize(int kind)
        {
            int max = 0;
            switch (kind)
            {
                case 0: max = Math.Max(rowCount[2], Math.Max(rowCount[1], rowCount[0x1B])); return max < (1 << 14) ? 2 : 4; // TypeDefOrRef
                case 1: max = Math.Max(rowCount[0], Math.Max(rowCount[0x1A], Math.Max(rowCount[0x23], rowCount[1]))); return max < (1 << 14) ? 2 : 4; // ResolutionScope
            }
            return 4;
        }

        private int RowLength(int t)
        {
            switch (t)
            {
                case 0x00: return 2 + strIdxSize + guidIdxSize * 3;
                case 0x01: return CodedSize(1) + strIdxSize * 2;
                case 0x02: return 4 + strIdxSize * 2 + CodedSize(0) + IdxSize(4) + IdxSize(6);
                case 0x03: return IdxSize(4);
                case 0x04: return 2 + strIdxSize + blobIdxSize;
                case 0x05: return IdxSize(6);
                case 0x06: return 4 + 2 + 2 + strIdxSize + blobIdxSize + IdxSize(8);
                default: return 0;
            }
        }

        public int TypeCount { get { return rowCount[2]; } }
        public int FieldCount { get { return rowCount[4]; } }
        public int MethodCount { get { return rowCount[6]; } }

        private int ReadIdx(int off, int size)
        {
            return size == 2 ? (int)BitConverter.ToUInt16(b, off) : (int)BitConverter.ToUInt32(b, off);
        }

        private string ReadStr(int off)
        {
            int idx = ReadIdx(off, strIdxSize);
            int s = stringsBase + idx;
            int e = s;
            while (b[e] != 0) e++;
            return Encoding.UTF8.GetString(b, s, e - s);
        }

        private int Cursor(int table, int row)
        {
            return rowOff[table] + row * rowLen[table];
        }

        public int TypeFieldList(int i)
        {
            int c = Cursor(2, i) + 4 + strIdxSize * 2 + CodedSize(0);
            return ReadIdx(c, IdxSize(4));
        }

        public int TypeMethodList(int i)
        {
            int c = Cursor(2, i) + 4 + strIdxSize * 2 + CodedSize(0) + IdxSize(4);
            return ReadIdx(c, IdxSize(6));
        }

        public string FieldName(int rid)
        {
            int c = Cursor(4, rid - 1) + 2;
            return ReadStr(c);
        }

        public string MethodName(int rid)
        {
            int c = Cursor(6, rid - 1) + 8;
            return ReadStr(c);
        }

        public bool FindClosureMembers(out uint cacheField, out uint instanceField, out uint lambdaMethod)
        {
            cacheField = 0; instanceField = 0; lambdaMethod = 0;
            for (int i = 0; i < rowCount[2]; i++)
            {
                int fs = TypeFieldList(i);
                int fe = (i + 1 < rowCount[2]) ? TypeFieldList(i + 1) : rowCount[4] + 1;
                int ms = TypeMethodList(i);
                int me = (i + 1 < rowCount[2]) ? TypeMethodList(i + 1) : rowCount[6] + 1;

                int f1 = -1, f2 = -1;
                for (int f = fs; f < fe && f <= rowCount[4]; f++)
                {
                    string n = FieldName(f);
                    if (n == "$IR3-3") f1 = f;
                    else if (n == "$I") f2 = f;
                }
                if (f1 < 0 || f2 < 0) continue;

                int m1 = -1;
                for (int m = ms; m < me && m <= rowCount[6]; m++)
                {
                    if (MethodName(m) == "_Lambda$__R3-3") { m1 = m; break; }
                }
                if (m1 < 0) continue;

                cacheField = 0x04000000u | (uint)f1;
                instanceField = 0x04000000u | (uint)f2;
                lambdaMethod = 0x06000000u | (uint)m1;
                return true;
            }
            return false;
        }

        public string TypeName(int rid)
        {
            return ReadStr(Cursor(2, rid - 1) + 4);
        }

        public int FindType(string name)
        {
            for (int i = 0; i < rowCount[2]; i++)
            {
                if (TypeName(i + 1) == name) return i + 1;
            }
            return 0;
        }

        public uint MethodRva(int rid)
        {
            return BitConverter.ToUInt32(b, Cursor(6, rid - 1));
        }

        public int FindMethod(int typeRid, string name)
        {
            if (typeRid <= 0) return 0;
            int i = typeRid - 1;
            int ms = TypeMethodList(i);
            int me = (i + 1 < rowCount[2]) ? TypeMethodList(i + 1) : rowCount[6] + 1;
            for (int m = ms; m < me && m <= rowCount[6]; m++)
            {
                if (MethodName(m) == name) return m;
            }
            return 0;
        }

        public int FindField(int typeRid, string name)
        {
            if (typeRid <= 0) return 0;
            int i = typeRid - 1;
            int fs = TypeFieldList(i);
            int fe = (i + 1 < rowCount[2]) ? TypeFieldList(i + 1) : rowCount[4] + 1;
            for (int f = fs; f < fe && f <= rowCount[4]; f++)
            {
                if (FieldName(f) == name) return f;
            }
            return 0;
        }
    }
    internal enum ItemState { None, NeedsFix, Fixed, Unknown }
    internal enum PickAction { None, Fix, Restore }

    internal sealed class LaunchItem
    {
        public string Path;
        public string FileName;
        public string Version;
        public bool IsCe;
        public long Size;
        public string Detail;
        public ItemState State;

        public string StateText
        {
            get
            {
                switch (State)
                {
                    case ItemState.NeedsFix: return "待修复";
                    case ItemState.Fixed: return "已修复";
                    case ItemState.None: return "无需修复";
                    default: return "无法识别";
                }
            }
        }

        public Color StateColor
        {
            get
            {
                switch (State)
                {
                    case ItemState.NeedsFix: return Color.FromArgb(206, 122, 12);
                    case ItemState.Fixed: return Color.FromArgb(28, 148, 88);
                    default: return Color.FromArgb(150, 155, 165);
                }
            }
        }
    }

    internal sealed class PickForm : Form
    {
        private static readonly Color Accent = Color.FromArgb(47, 111, 237);
        private static readonly Color TextMain = Color.FromArgb(30, 34, 42);
        private static readonly Color TextSub = Color.FromArgb(128, 134, 146);
        private static readonly Color SelectedBg = Color.FromArgb(235, 242, 255);
        private static readonly Color HoverBg = Color.FromArgb(247, 248, 250);
        private static readonly Color Disabled = Color.FromArgb(196, 200, 208);

        private readonly List<LaunchItem> items;
        private readonly ListBox list;
        private int hoverIndex = -1;
        private readonly Button btnFix;
        private readonly Button btnRestore;

        public PickAction Action = PickAction.None;
        public int SelectedIndex = -1;

        public PickForm(List<LaunchItem> listItems)
        {
            items = listItems;
            Text = "PCL2 下载修复工具";
            FormBorderStyle = FormBorderStyle.FixedSingle;
            MaximizeBox = false;
            MinimizeBox = false;
            ShowIcon = false;
            DoubleBuffered = true;
            StartPosition = FormStartPosition.CenterScreen;
            int listH = Math.Min(items.Count, 4) * 66;
            ClientSize = new Size(560, 88 + listH + 74);
            BackColor = Color.White;
            Font = new Font("Microsoft YaHei UI", 9f);

            var title = new Label();
            title.Text = items.Count > 1 ? "找到多个 PCL2 启动器" : "检测到 PCL2 启动器";
            title.Font = new Font("Microsoft YaHei UI", 14f, FontStyle.Bold);
            title.ForeColor = TextMain;
            title.SetBounds(20, 18, 500, 30);
            title.BackColor = Color.Transparent;

            var sub = new Label();
            sub.Text = "「修复」解锁下载功能 · 「回退」还原成未修复状态";
            sub.Font = new Font("Microsoft YaHei UI", 9f);
            sub.ForeColor = TextSub;
            sub.SetBounds(22, 50, 500, 20);
            sub.BackColor = Color.Transparent;

            var line = new Panel();
            line.BackColor = Color.FromArgb(232, 235, 240);
            line.SetBounds(20, 78, 520, 1);

            list = new ListBox();
            list.SetBounds(12, 88, 536, listH + 2);
            list.BorderStyle = BorderStyle.None;
            list.DrawMode = DrawMode.OwnerDrawFixed;
            list.ItemHeight = 66;
            list.IntegralHeight = false;
            list.BackColor = Color.White;
            list.Font = new Font("Microsoft YaHei UI", 10f);
            foreach (var it in items) list.Items.Add(it.FileName);
            list.DrawItem += new DrawItemEventHandler(OnDrawItem);
            list.MouseMove += new MouseEventHandler(OnMouseMove);
            list.MouseLeave += new EventHandler(OnMouseLeave);
            list.DoubleClick += new EventHandler(OnDoubleClick);
            if (items.Count > 0) list.SelectedIndex = 0;
            list.SelectedIndexChanged += new EventHandler(OnSelectionChanged);

            int y = 88 + listH + 24;
            btnFix = MakeButton("修复", 252, y, 96, true);
            btnFix.Click += new EventHandler(OnFix);
            btnRestore = MakeButton("回退", 356, y, 96, false);
            btnRestore.Click += new EventHandler(OnRestore);
            var cancel = MakeButton("取消", 460, y, 80, false);
            cancel.DialogResult = DialogResult.Cancel;

            Controls.Add(title);
            Controls.Add(sub);
            Controls.Add(line);
            Controls.Add(list);
            Controls.Add(btnFix);
            Controls.Add(btnRestore);
            Controls.Add(cancel);
            CancelButton = cancel;
            UpdateButtons();
        }

        private Button MakeButton(string text, int x, int y, int w, bool primary)
        {
            var b = new Button();
            b.Text = text;
            b.Font = new Font("Microsoft YaHei UI", 9.5f, primary ? FontStyle.Bold : FontStyle.Regular);
            b.SetBounds(x, y, w, 34);
            b.FlatStyle = FlatStyle.Flat;
            b.BackColor = primary ? Accent : Color.White;
            b.ForeColor = primary ? Color.White : TextMain;
            b.FlatAppearance.BorderSize = primary ? 0 : 1;
            b.FlatAppearance.BorderColor = Color.FromArgb(214, 218, 224);
            b.Cursor = Cursors.Hand;
            b.EnabledChanged += new EventHandler(OnButtonEnabledChanged);
            return b;
        }

        private void OnButtonEnabledChanged(object sender, EventArgs e)
        {
            var b = (Button)sender;
            if (b.Enabled) return;
            b.BackColor = Color.FromArgb(243, 244, 246);
            b.ForeColor = Disabled;
            b.FlatAppearance.BorderColor = Color.FromArgb(228, 230, 234);
        }

        private void UpdateButtons()
        {
            int i = list.SelectedIndex;
            ItemState st = (i >= 0 && i < items.Count) ? items[i].State : ItemState.Unknown;
            btnFix.Enabled = st == ItemState.NeedsFix;
            btnRestore.Enabled = st == ItemState.Fixed;
            AcceptButton = btnFix.Enabled ? btnFix : (btnRestore.Enabled ? btnRestore : null);
        }

        private void OnSelectionChanged(object sender, EventArgs e)
        {
            UpdateButtons();
        }

        private void OnMouseMove(object sender, MouseEventArgs e)
        {
            int idx = list.IndexFromPoint(e.Location);
            if (idx != hoverIndex)
            {
                hoverIndex = idx;
                list.Invalidate();
            }
        }

        private void OnMouseLeave(object sender, EventArgs e)
        {
            hoverIndex = -1;
            list.Invalidate();
        }

        private void OnDrawItem(object sender, DrawItemEventArgs e)
        {
            if (e.Index < 0 || e.Index >= items.Count) return;
            var it = items[e.Index];
            bool selected = (e.State & DrawItemState.Selected) == DrawItemState.Selected;
            Rectangle b = e.Bounds;

            Color bg = selected ? SelectedBg : (e.Index == hoverIndex ? HoverBg : Color.White);
            using (var brush = new SolidBrush(bg)) e.Graphics.FillRectangle(brush, b);

            if (selected)
            {
                using (var brush = new SolidBrush(Accent))
                    e.Graphics.FillRectangle(brush, new Rectangle(b.X + 2, b.Y + 10, 3, b.Height - 20));
            }

            if (e.Index > 0)
            {
                using (var pen = new Pen(Color.FromArgb(240, 242, 245)))
                    e.Graphics.DrawLine(pen, b.X + 16, b.Y, b.Right - 16, b.Y);
            }

            using (var f = new Font("Microsoft YaHei UI", 10.5f, FontStyle.Bold))
            using (var brush = new SolidBrush(TextMain))
                e.Graphics.DrawString(it.FileName, f, brush, b.X + 18, b.Y + 9);

            using (var f = new Font("Microsoft YaHei UI", 8.6f))
            using (var brush = new SolidBrush(TextSub))
                e.Graphics.DrawString(it.Detail, f, brush, b.X + 18, b.Y + 35);

            using (var f = new Font("Microsoft YaHei UI", 9f, FontStyle.Bold))
            using (var brush = new SolidBrush(it.StateColor))
            {
                SizeF sz = e.Graphics.MeasureString(it.StateText, f);
                e.Graphics.DrawString(it.StateText, f, brush, b.Right - sz.Width - 22, b.Y + 12);
            }
        }

        private void OnDoubleClick(object sender, EventArgs e)
        {
            if (btnFix.Enabled) OnFix(sender, e);
            else if (btnRestore.Enabled) OnRestore(sender, e);
        }

        private void OnFix(object sender, EventArgs e)
        {
            SelectedIndex = list.SelectedIndex;
            Action = PickAction.Fix;
            DialogResult = DialogResult.OK;
            Close();
        }

        private void OnRestore(object sender, EventArgs e)
        {
            SelectedIndex = list.SelectedIndex;
            Action = PickAction.Restore;
            DialogResult = DialogResult.OK;
            Close();
        }
    }

    internal static class Program
    {
        private const string PreferredName = "Plain Craft Launcher 2.exe";
        private const string BackupFolder = "PCL2修复备份";
        private const int BlockLength = 48;
        private static readonly StringBuilder LogBuf = new StringBuilder();
        private static bool silent;
        private static bool restoreMode;

        [STAThread]
        private static void Main(string[] args)
        {
            silent = Array.IndexOf(args, "--silent") >= 0;
            restoreMode = Array.IndexOf(args, "--restore") >= 0;
            int code;
            try
            {
                code = Run();
            }
            catch (Exception ex)
            {
                Log("异常：" + ex.Message);
                code = 4;
                if (!silent) Box(ex.Message, "PCL2 下载修复工具 - 出错", MessageBoxIcon.Error);
            }
            if (silent)
            {
                try { File.WriteAllText(Path.Combine(AppDir, "fix-log.txt"), LogBuf.ToString(), new UTF8Encoding(false)); }
                catch { }
                Environment.Exit(code);
            }
        }

        private static string AppDir
        {
            get { return AppDomain.CurrentDomain.BaseDirectory; }
        }

        private static int Run()
        {
            string dir = AppDir;
            Log("工具目录：" + dir);

            List<LaunchItem> candidates = FindCandidates(dir);
            if (candidates.Count == 0)
            {
                return Fail("在工具所在文件夹里没有找到 PCL2 启动器。\r\n\r\n" +
                            "请把本工具放到 PCL2 所在的文件夹（和启动器 exe 同一目录）后再双击运行。\r\n\r\n" +
                            "启动器改过名字（比如 pcl2.exe）没有关系，工具会自动识别；\r\n" +
                            "但它的扩展名需要是 .exe。\r\n\r\n当前目录：" + dir);
            }

            LaunchItem chosen;
            PickAction action;
            if (silent)
            {
                chosen = candidates[0];
                action = restoreMode ? PickAction.Restore : PickAction.Fix;
            }
            else
            {
                using (var pick = new PickForm(candidates))
                {
                    if (pick.ShowDialog() != DialogResult.OK || pick.Action == PickAction.None)
                    {
                        Log("用户取消。");
                        return 1;
                    }
                    action = pick.Action;
                    if (pick.SelectedIndex < 0) return 1;
                    chosen = candidates[pick.SelectedIndex];
                }
            }

            Log("目标文件：" + chosen.Path);
            Log("启动器版本：" + chosen.Version + "，类型：" + (chosen.IsCe ? "社区版" : "官方版") +
                "，状态：" + chosen.StateText);

            return action == PickAction.Restore ? DoRestore(chosen) : DoFix(chosen);
        }

        private static int DoFix(LaunchItem item)
        {
            string exe = item.Path;
            byte[] data;
            string err = ReadExclusive(exe, out data);
            if (err != null) return Fail(err);

            Log("原始 SHA256：" + Sha256(data));

            if (item.State == ItemState.None)
            {
                if (!silent)
                {
                    Box((item.IsCe ? "这是 PCL2 社区版，自带下载功能，不需要修复。" : "这个启动器里没有下载限制，不需要修复。") +
                        "\r\n\r\n启动器：" + item.FileName + "\r\n版本：" + item.Version + "\r\n\r\n" +
                        "直接打开 PCL2 → 下载 → 原版游戏 即可。",
                        "PCL2 下载修复工具", MessageBoxIcon.Information);
                }
                return 2;
            }
            if (item.State == ItemState.Fixed)
            {
                if (!silent)
                {
                    Box("这个启动器已经修复过了，不需要重复操作。\r\n\r\n" +
                        "启动器：" + item.FileName + "\r\n版本：" + item.Version + "\r\n\r\n" +
                        "如果想改回未修复状态，点「回退」即可。",
                        "PCL2 下载修复工具", MessageBoxIcon.Information);
                }
                return 2;
            }
            if (item.State == ItemState.Unknown)
            {
                return Fail("这个启动器里有下载限制的痕迹，但无法解析它的结构。\r\n\r\n" +
                            "启动器：" + item.FileName + "\r\n版本：" + item.Version + "\r\n\r\n" +
                            "可能它不是官方 PCL2，或版本结构已经变化。文件未做任何修改。");
            }

            PeImage img;
            try
            {
                img = new PeImage(data);
                var us = UsHeap.Build(img);
                uint tokNotice = us.FindToken("关闭下载");
                uint tokMain = us.FindToken("DlClientList Main");
                uint fieldToken = FindLoaderFieldToken(img, tokMain);
                int p = FindStub(img, tokNotice);
                if (p < 0) return Fail("没有找到需要修复的位置，文件未做任何修改。");

                Log(string.Format("补丁点偏移：文件 0x{0:X}", p));
                bool hadHidden = FindHidden(img, false) != null;
                byte[] patched = (byte[])data.Clone();
                patched[p] = 0x7E;
                BitConverter.GetBytes(fieldToken).CopyTo(patched, p + 1);
                patched[p + 5] = 0x2B;
                patched[p + 6] = (byte)(BlockLength - 7);
                for (int i = p + 7; i < p + BlockLength; i++) patched[i] = 0x00;
                PatchHidden(patched, img);

                var check = new PeImage(patched);
                if (FindPatched(check, fieldToken) < 0)
                    return Fail("内部自检失败，已放弃修改。文件未做任何修改。");
                if (hadHidden && FindHidden(check, false) != null)
                    return Fail("隐藏的下载入口还原失败，已放弃修改。文件未做任何修改。");

                string backupPath = MakeBackup(exe, item.Version, data);
                Log("备份：" + backupPath);
                File.WriteAllBytes(exe, patched);
                Log("修复后 SHA256：" + Sha256(patched));
                Log("完成。");

                if (!silent)
                {
                    Box("修复完成！\r\n\r\n" +
                        "启动器：" + item.FileName + "\r\n版本：" + item.Version + "\r\n\r\n" +
                        "备份文件：\r\n" + backupPath + "\r\n\r\n" +
                        "现在打开 PCL2 → 下载 → 原版游戏，就能看到版本列表了。\r\n" +
                        "（PCL 自动更新后补丁会失效，到时再双击本工具一次即可。）",
                        "PCL2 下载修复工具 - 成功", MessageBoxIcon.Information);
                }
                return 0;
            }
            catch (Exception ex)
            {
                Log("修复失败：" + ex.Message);
                return Fail("修复过程中出错，文件未做修改：\r\n" + ex.Message);
            }
        }

        private static int DoRestore(LaunchItem item)
        {
            string exe = item.Path;
            byte[] data;
            string err = ReadExclusive(exe, out data);
            if (err != null) return Fail(err);

            Log("当前 SHA256：" + Sha256(data));

            if (item.State != ItemState.Fixed)
            {
                if (!silent)
                {
                    Box("这个启动器当前不是「已修复」状态，不需要回退。\r\n\r\n" +
                        "启动器：" + item.FileName + "\r\n版本：" + item.Version + "\r\n状态：" + item.StateText,
                        "PCL2 下载修复工具", MessageBoxIcon.Information);
                }
                return 2;
            }

            byte[] restored = null;
            string how = null;

            string backupDir = Path.Combine(AppDir, BackupFolder);
            string backup = FindMatchingBackup(data, backupDir);
            if (backup != null)
            {
                restored = File.ReadAllBytes(backup);
                how = "还原方式：使用修复前的备份\r\n" + backup;
                Log("使用备份回退：" + backup);
            }
            else
            {
                Log("没有可用备份，改为直接重建原始代码。");
                var img = new PeImage(data);
                var heap = UsHeap.Build(img);
                uint fieldToken = FindLoaderFieldToken(img, heap.FindToken("DlClientList Main"));
                int p = FindPatched(img, fieldToken);
                if (p < 0) return Fail("没有找到之前的修改位置，无法回退。文件未做任何修改。");
                string why;
                restored = RebuildStub(img, p, out why);
                if (restored == null)
                {
                    return Fail("没有备份，而且无法按原逻辑重建这段代码：\r\n" + why +
                                "\r\n\r\n文件未做任何修改。");
                }
                RestoreHidden(restored, img);
                how = "还原方式：直接重建原始代码（没有使用备份）";
                Log(string.Format("已重建补丁区域：0x{0:X}", p));
            }

            try { File.WriteAllBytes(exe, restored); }
            catch (Exception ex) { return Fail("写入失败：" + ex.Message); }

            // 自检：补丁必须消失，且仍然是有效的 .NET 程序
            try
            {
                var chk = new PeImage(restored);
                var heap2 = UsHeap.Build(chk);
                uint ft = FindLoaderFieldToken(chk, heap2.FindToken("DlClientList Main"));
                if (FindPatched(chk, ft) >= 0) return Fail("回退后自检未通过（补丁仍然存在）。");
            }
            catch (Exception ex) { return Fail("回退后自检未通过：" + ex.Message); }

            Log("回退后 SHA256：" + Sha256(restored));

            if (!silent)
            {
                Box("已回退到未修复状态。\r\n\r\n" +
                    "启动器：" + item.FileName + "\r\n版本：" + item.Version + "\r\n\r\n" +
                    how + "\r\n\r\n" +
                    "现在这个启动器的「下载 → 原版游戏」会恢复成原来的样子。\r\n" +
                    "需要的话，随时可以再点「修复」。",
                    "PCL2 下载修复工具 - 已回退", MessageBoxIcon.Information);
            }
            return 0;
        }

        // 没有备份时，按原始编译结果把 48 字节的占位加载器重新拼出来
        private static byte[] RebuildStub(PeImage img, int p, out string error)
        {
            error = null;
            var heap = UsHeap.Build(img);
            uint tokNotice = heap.FindToken("关闭下载");
            if (tokNotice == 0) { error = "找不到「关闭下载」字符串"; return null; }

            var mt = new MetaTables(img);
            uint cacheField, instanceField, lambdaMethod;
            if (!mt.FindClosureMembers(out cacheField, out instanceField, out lambdaMethod))
            {
                error = "在元数据里找不到闭包类型的缓存字段";
                return null;
            }

            // 同一个 Action<T> 构造函数在紧跟着的 onFinish 里还在，直接复用
            uint actionCtor = BitConverter.ToUInt32(img.B, p + 56);
            // LoaderTask<TIn,TOut> 构造函数从 ModDownload..cctor 里取
            uint loaderCtor = FindLoaderCtorToken(img, heap.FindToken("DlClientList Main"));
            if (loaderCtor == 0) { error = "找不到 LoaderTask 构造函数引用"; return null; }

            byte[] o = (byte[])img.B.Clone();
            int i = p;
            o[i++] = 0x72; WriteU32(o, i, tokNotice); i += 4;
            o[i++] = 0x7E; WriteU32(o, i, cacheField); i += 4;
            o[i++] = 0x2C; o[i++] = 0x07;
            o[i++] = 0x7E; WriteU32(o, i, cacheField); i += 4;
            o[i++] = 0x2B; o[i++] = 0x16;
            o[i++] = 0x7E; WriteU32(o, i, instanceField); i += 4;
            o[i++] = 0xFE; o[i++] = 0x06; WriteU32(o, i, lambdaMethod); i += 4;
            o[i++] = 0x73; WriteU32(o, i, actionCtor); i += 4;
            o[i++] = 0x25;
            o[i++] = 0x80; WriteU32(o, i, cacheField); i += 4;
            o[i++] = 0x14;
            o[i++] = 0x18;
            o[i++] = 0x73; WriteU32(o, i, loaderCtor); i += 4;
            return o;
        }

        private static void WriteU32(byte[] b, int off, uint v)
        {
            b[off] = (byte)v;
            b[off + 1] = (byte)(v >> 8);
            b[off + 2] = (byte)(v >> 16);
            b[off + 3] = (byte)(v >> 24);
        }

        private static uint FindLoaderCtorToken(PeImage img, uint tokMain)
        {
            byte[] b = img.B;
            int start = (int)img.TextStart;
            int end = start + (int)img.TextSize - 32;
            for (int i = start; i < end; i++)
            {
                if (b[i] != 0x72) continue;
                if (BitConverter.ToUInt32(b, i + 1) != tokMain) continue;
                if (b[i + 5] != 0x14) continue;
                if (b[i + 6] != 0xFE || b[i + 7] != 0x06) continue;
                if (b[i + 12] != 0x73) continue;
                if (b[i + 17] != 0x14) continue;
                if (b[i + 18] != 0x18) continue;
                if (b[i + 19] != 0x73) continue;
                return BitConverter.ToUInt32(b, i + 20);
            }
            return 0;
        }
        private static string ReadExclusive(string exe, out byte[] data)
        {
            data = null;
            try
            {
                using (var fs = new FileStream(exe, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
                {
                    data = new byte[fs.Length];
                    int read = 0;
                    while (read < data.Length)
                    {
                        int n = fs.Read(data, read, data.Length - read);
                        if (n <= 0) break;
                        read += n;
                    }
                }
                return null;
            }
            catch (IOException)
            {
                return "PCL2 似乎正在运行，文件被占用。\r\n\r\n请先完全关闭启动器，然后再运行本工具。";
            }
            catch (UnauthorizedAccessException)
            {
                return "没有权限写入该文件。\r\n\r\n请确认 PCL2 已关闭；如果启动器放在受保护目录（如 Program Files），请把整个文件夹移动到普通目录后再试。";
            }
        }

        private static string FindMatchingBackup(byte[] current, string backupDir)
        {
            if (!Directory.Exists(backupDir)) return null;
            string[] files;
            try { files = Directory.GetFiles(backupDir, "*.bak"); }
            catch { return null; }
            Array.Sort(files);
            for (int i = files.Length - 1; i >= 0; i--)
            {
                byte[] b;
                try { b = File.ReadAllBytes(files[i]); }
                catch { continue; }
                if (b.Length != current.Length) continue;
                int count = 0;
                bool ok = true;
                for (int k = 0; k < b.Length; k++)
                {
                    if (b[k] == current[k]) continue;
                    count++;
                    if (count > 256) { ok = false; break; }
                }
                if (!ok || count == 0) continue;
                return files[i];
            }
            return null;
        }

        private static List<LaunchItem> FindCandidates(string dir)
        {
            var result = new List<LaunchItem>();
            string self = Path.GetFullPath(Process.GetCurrentProcess().MainModule.FileName);

            string preferred = Path.Combine(dir, PreferredName);
            if (File.Exists(preferred) && IsLauncher(preferred)) result.Add(MakeItem(preferred));

            string[] files;
            try { files = Directory.GetFiles(dir, "*.exe"); }
            catch { files = new string[0]; }
            Array.Sort(files, StringComparer.OrdinalIgnoreCase);

            foreach (string f in files)
            {
                if (string.Equals(Path.GetFullPath(f), self, StringComparison.OrdinalIgnoreCase)) continue;
                if (string.Equals(Path.GetFullPath(f), Path.GetFullPath(preferred), StringComparison.OrdinalIgnoreCase)) continue;
                if (IsLauncher(f))
                {
                    Log("候选：" + Path.GetFileName(f));
                    result.Add(MakeItem(f));
                }
            }
            return result;
        }

        private static LaunchItem MakeItem(string path)
        {
            var item = new LaunchItem();
            item.Path = path;
            item.FileName = Path.GetFileName(path);
            item.Version = "未知";
            string product = "";
            try
            {
                var vi = FileVersionInfo.GetVersionInfo(path);
                if (!string.IsNullOrEmpty(vi.FileVersion)) item.Version = vi.FileVersion;
                product = (vi.ProductName ?? "") + " " + (vi.FileDescription ?? "");
            }
            catch { }
            item.IsCe = product.IndexOf("Community Edition", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        product.IndexOf("社区版", StringComparison.Ordinal) >= 0;
            try { item.Size = new FileInfo(path).Length; } catch { item.Size = 0; }
            item.Detail = "版本 " + item.Version + "  ·  " + (item.IsCe ? "社区版" : "官方版") +
                          "  ·  " + (item.Size / 1024.0 / 1024.0).ToString("0.0") + " MB";
            item.State = DetectState(path);
            return item;
        }

        private static ItemState DetectState(string path)
        {
            try
            {
                byte[] data = File.ReadAllBytes(path);
                if (IndexOfBytes(data, Encoding.Unicode.GetBytes("关闭下载")) < 0) return ItemState.None;
                var img = new PeImage(data);
                var us = UsHeap.Build(img);
                uint fieldToken = FindLoaderFieldToken(img, us.FindToken("DlClientList Main"));
                if (fieldToken == 0) return ItemState.Unknown;
                if (FindPatched(img, fieldToken) >= 0) return ItemState.Fixed;
                if (FindStub(img, us.FindToken("关闭下载")) >= 0) return ItemState.NeedsFix;
                return ItemState.Unknown;
            }
            catch
            {
                return ItemState.Unknown;
            }
        }

        private static bool IsLauncher(string path)
        {
            try
            {
                if (!File.Exists(path)) return false;
                byte[] data = File.ReadAllBytes(path);
                if (IndexOfBytes(data, Encoding.Unicode.GetBytes("PCL2DF-TOOL-MARKER")) >= 0) return false;
                var vi = FileVersionInfo.GetVersionInfo(path);
                string product = (vi.ProductName ?? "") + " " + (vi.FileDescription ?? "");
                if (product.IndexOf("Plain Craft Launcher", StringComparison.OrdinalIgnoreCase) >= 0) return true;
                if (IndexOfBytes(data, Encoding.Unicode.GetBytes("DlClientList Main")) < 0) return false;
                return IndexOfBytes(data, Encoding.Unicode.GetBytes("关闭下载")) >= 0;
            }
            catch { return false; }
        }

        private static uint FindLoaderFieldToken(PeImage img, uint tokMain)
        {
            byte[] b = img.B;
            int start = (int)img.TextStart;
            int end = start + (int)img.TextSize - 32;
            for (int i = start; i < end; i++)
            {
                if (b[i] != 0x72) continue;
                if (BitConverter.ToUInt32(b, i + 1) != tokMain) continue;
                if (b[i + 5] != 0x14) continue;
                if (b[i + 6] != 0xFE || b[i + 7] != 0x06) continue;
                if (b[i + 12] != 0x73) continue;
                if (b[i + 17] != 0x14) continue;
                if (b[i + 18] != 0x18) continue;
                if (b[i + 19] != 0x73) continue;
                if (b[i + 24] != 0x80) continue;
                return BitConverter.ToUInt32(b, i + 25);
            }
            return 0;
        }

        private static int FindStub(PeImage img, uint tokNotice)
        {
            byte[] b = img.B;
            int start = (int)img.TextStart;
            int end = start + (int)img.TextSize - BlockLength - 24;
            for (int i = start; i < end; i++)
            {
                if (b[i] != 0x72) continue;
                if (BitConverter.ToUInt32(b, i + 1) != tokNotice) continue;
                if (b[i + 5] != 0x7E) continue;
                if (b[i + 10] != 0x2C || b[i + 11] != 0x07) continue;
                if (b[i + 12] != 0x7E) continue;
                if (b[i + 17] != 0x2B || b[i + 18] != 0x16) continue;
                if (b[i + 19] != 0x7E) continue;
                if (b[i + 24] != 0xFE || b[i + 25] != 0x06) continue;
                if (b[i + 30] != 0x73) continue;
                if (b[i + 35] != 0x25) continue;
                if (b[i + 36] != 0x80) continue;
                if (b[i + 41] != 0x14) continue;
                if (b[i + 42] != 0x18) continue;
                if (b[i + 43] != 0x73) continue;
                if (b[i + 48] != 0x02) continue;
                uint a = BitConverter.ToUInt32(b, i + 6);
                if (BitConverter.ToUInt32(b, i + 13) != a) continue;
                if (BitConverter.ToUInt32(b, i + 37) != a) continue;
                if (b[i + 49] != 0xFE || b[i + 50] != 0x06) continue;
                if (b[i + 55] != 0x73) continue;
                if (b[i + 60] != 0x14 || b[i + 61] != 0x17) continue;
                if (b[i + 62] != 0x28) continue;
                if (b[i + 67] != 0x2A) continue;
                return i;
            }
            return -1;
        }

        private static int FindPatched(PeImage img, uint fieldToken)
        {
            byte[] b = img.B;
            int start = (int)img.TextStart;
            int end = start + (int)img.TextSize - BlockLength - 24;
            for (int i = start; i < end; i++)
            {
                if (b[i] != 0x7E) continue;
                if (BitConverter.ToUInt32(b, i + 1) != fieldToken) continue;
                if (b[i + 5] != 0x2B || b[i + 6] != (byte)(BlockLength - 7)) continue;
                bool ok = true;
                for (int k = i + 7; k < i + BlockLength; k++) { if (b[k] != 0x00) { ok = false; break; } }
                if (!ok) continue;
                if (b[i + 48] != 0x02) continue;
                if (b[i + 49] != 0xFE || b[i + 50] != 0x06) continue;
                if (b[i + 55] != 0x73) continue;
                if (b[i + 60] != 0x14 || b[i + 61] != 0x17) continue;
                if (b[i + 62] != 0x28) continue;
                if (b[i + 67] != 0x2A) continue;
                return i;
            }
            return -1;
        }

        // ---------- PCL 2.99.0.1：PageDownloadLeft 构造器里隐藏下载入口 ----------
        private sealed class HiddenEntry
        {
            public int VisInstall, VisResource, PageId, Checked;
            public uint TokInstall, TokMod, TokLab, PageIdField;
        }

        private static HiddenEntry FindHidden(PeImage img, bool patched)
        {
            try
            {
                var mt = new MetaTables(img);
                int type = mt.FindType("PageDownloadLeft");
                if (type == 0) return null;
                int ctor = mt.FindMethod(type, ".ctor");
                int rInstall = mt.FindMethod(type, "get_ItemInstall");
                int rMod = mt.FindMethod(type, "get_ItemMod");
                int rLab = mt.FindMethod(type, "get_LabResource");
                int rPage = mt.FindField(type, "PageID");
                if (ctor == 0 || rInstall == 0 || rLab == 0 || rPage == 0) return null;

                int off, size;
                LocateBody(img, mt.MethodRva(ctor), out off, out size);
                if (off <= 0 || size <= 0) return null;

                byte value = patched ? (byte)0x16 : (byte)0x18;
                var h = new HiddenEntry();
                h.TokInstall = 0x06000000u | (uint)rInstall;
                h.TokMod = 0x06000000u | (uint)rMod;
                h.TokLab = 0x06000000u | (uint)rLab;
                h.PageIdField = 0x04000000u | (uint)rPage;

                h.VisInstall = FindCallSeq(img.B, off, size, h.TokInstall, value);
                h.VisResource = FindCallSeq(img.B, off, size, h.TokLab, value);
                if (h.VisInstall < 0 || h.VisResource < 0) return null;
                h.PageId = FindPageIdAssign(img.B, off, size, h.VisResource, h.PageIdField, value);
                h.Checked = FindCheckedSeq(img.B, off, size, patched ? h.TokInstall : h.TokMod);
                if (h.PageId < 0 || h.Checked < 0) return null;
                return h;
            }
            catch { return null; }
        }

        private static int FindCallSeq(byte[] b, int off, int size, uint token, byte after)
        {
            for (int i = off; i < off + size - 6; i++)
            {
                if (b[i] != 0x6F) continue;
                if (BitConverter.ToUInt32(b, i + 1) != token) continue;
                if (b[i + 5] != after) continue;
                return i;
            }
            return -1;
        }

        private static int FindPageIdAssign(byte[] b, int off, int size, int from, uint field, byte value)
        {
            for (int i = Math.Max(from, off); i < off + size - 7; i++)
            {
                if (b[i] != 0x02) continue;
                if (b[i + 1] != value) continue;
                if (b[i + 2] != 0x7D) continue;
                if (BitConverter.ToUInt32(b, i + 3) != field) continue;
                return i;
            }
            return -1;
        }

        private static int FindCheckedSeq(byte[] b, int off, int size, uint token)
        {
            for (int i = off; i < off + size - 10; i++)
            {
                if (b[i] != 0x02 || b[i + 1] != 0x6F) continue;
                if (BitConverter.ToUInt32(b, i + 2) != token) continue;
                if (b[i + 6] != 0x17) continue;
                if (b[i + 7] != 0x6F) continue;
                return i;
            }
            return -1;
        }

        private static void LocateBody(PeImage img, uint rva, out int off, out int size)
        {
            off = -1; size = 0;
            int start = (int)img.RvaToOffset(rva);
            byte first = img.B[start];
            if ((first & 3) == 2) { size = first >> 2; off = start + 1; return; }
            ushort flags = BitConverter.ToUInt16(img.B, start);
            size = BitConverter.ToInt32(img.B, start + 4);
            off = start + ((flags >> 12) * 4);
        }

        // 把隐藏代码改成显示代码（可见性 2/0 → 0，PageID 2 → 0，选中项改成原版游戏）
        private static bool PatchHidden(byte[] o, PeImage img)
        {
            var h = FindHidden(img, false);
            if (h == null) return false;
            o[h.VisInstall + 5] = 0x16;
            o[h.VisResource + 5] = 0x16;
            o[h.PageId + 1] = 0x16;
            WriteU32(o, h.Checked + 2, h.TokInstall);
            Log(string.Format("隐藏入口已还原：可见性 @ {0}/{1}，PageID @ {2}，选中项 @ {3}",
                              h.VisInstall, h.VisResource, h.PageId, h.Checked));
            return true;
        }

        // 反向：显示改回隐藏、PageID 改回下载页、选中项改回整合包
        private static bool RestoreHidden(byte[] o, PeImage img)
        {
            var h = FindHidden(img, true);
            if (h == null) return false;
            o[h.VisInstall + 5] = 0x18;
            o[h.VisResource + 5] = 0x18;
            o[h.PageId + 1] = 0x18;
            WriteU32(o, h.Checked + 2, h.TokMod);
            Log(string.Format("隐藏入口已恢复：可见性 @ {0}/{1}，PageID @ {2}，选中项 @ {3}",
                              h.VisInstall, h.VisResource, h.PageId, h.Checked));
            return true;
        }

        private static int IndexOfBytes(byte[] hay, byte[] needle)
        {
            for (int i = 0; i <= hay.Length - needle.Length; i++)
            {
                bool ok = true;
                for (int j = 0; j < needle.Length; j++) { if (hay[i + j] != needle[j]) { ok = false; break; } }
                if (ok) return i;
            }
            return -1;
        }

        private static string MakeBackup(string exe, string version, byte[] data)
        {
            string dir = Path.Combine(AppDir, BackupFolder);
            Directory.CreateDirectory(dir);
            string name = string.Format("{0}_{1}_{2}.bak", Safe(Path.GetFileNameWithoutExtension(exe)), Safe(version),
                                        DateTime.Now.ToString("yyyyMMdd-HHmmss"));
            string path = Path.Combine(dir, name);
            File.WriteAllBytes(path, data);
            return path;
        }

        private static string Safe(string s)
        {
            if (s == null) return "unknown";
            return s.Replace('\\', '_').Replace('/', '_').Replace(':', '_').Replace('*', '_').Replace('?', '_');
        }

        private static int Fail(string message)
        {
            Log("失败：" + message.Replace("\r\n", " "));
            if (!silent) Box(message, "PCL2 下载修复工具 - 未能完成", MessageBoxIcon.Warning);
            return 3;
        }

        private static void Box(string text, string title, MessageBoxIcon icon)
        {
            MessageBox.Show(text, title, MessageBoxButtons.OK, icon);
        }

        private static void Log(string line)
        {
            LogBuf.AppendLine(DateTime.Now.ToString("HH:mm:ss") + "  " + line);
        }

        private static string Sha256(byte[] data)
        {
            using (var sha = SHA256.Create())
            {
                byte[] h = sha.ComputeHash(data);
                var sb = new StringBuilder(h.Length * 2);
                foreach (byte x in h) sb.Append(x.ToString("x2"));
                return sb.ToString();
            }
        }
    }
}
