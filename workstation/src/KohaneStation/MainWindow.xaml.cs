using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Media.Imaging;
using Windows.ApplicationModel.DataTransfer;
using Windows.Storage;
using Windows.Storage.Pickers;
using WinRT.Interop;

namespace KohaneStation;

/// <summary>One row of the property table (label on the left, value on the right).</summary>
public sealed class PropRow
{
    public string Label { get; init; } = "";
    public string Value { get; init; } = "";
}

/// <summary>One row of the library attribute list.</summary>
public sealed class IndexRow
{
    public string Kind { get; init; } = "";
    public string Name { get; init; } = "";
    public string Source { get; init; } = "";
    public string Path { get; init; } = "";

    /// <summary>Working-tree decoration: the letter an editor badges the file with, and its colour.</summary>
    public string StatusLetter { get; set; } = "—";
    public Brush StatusBrush { get; set; } = null!;
}

/// <summary>One row of the capability directory (kohane's own plugin family).</summary>
public sealed class CapRow
{
    public string Name { get; init; } = "";
    public string Role { get; init; } = "";
    public string Link { get; init; } = "";
}

/// <summary>
/// Main window: a Kohane-index workstation. Left panel = instant file analyzer
/// (DiskInfo-flavoured), right panel = DIY library/index workbench (Fruity-Wrapper
/// flavoured) with kohane's own capability directory beside it. Both talk to the pure-Node
/// engine over a local HTTP bridge that reuses the kohane-index-desuno MCP tool layer.
/// </summary>
public sealed partial class MainWindow : Window
{
    private const string Bridge = "http://127.0.0.1:8787";

    private WaterfallView? _waterfall;

    private readonly HttpClient _http = new();
    private JsonElement? _lastResult;
    private JsonElement? _lastVcs;
    private bool _capabilitiesLoaded;

    public MainWindow()
    {
        App.Trace("MainWindow ctor: enter");
        InitializeComponent();
        App.Trace("MainWindow ctor: InitializeComponent done");

        Title = "kohane-index-desuno 工作站";
        _ = InitEngineStatusAsync();

        ShowIdleTable();
        App.Trace("MainWindow ctor: ready");

        // Headless smoke hooks: point KOHANE_STATION_SMOKE at a file and the shell analyses it at
        // startup exactly as if it had been dropped in; add KOHANE_STATION_SMOKE_RECORD=1 to record it
        // and refresh the index panel, or KOHANE_STATION_SMOKE_CAPS=1 to open the capability view.
        var smoke = Environment.GetEnvironmentVariable("KOHANE_STATION_SMOKE");
        if (!string.IsNullOrWhiteSpace(smoke))
        {
            App.Trace("smoke: analysing " + smoke);
            PathBox.Text = smoke;
            _ = RunSmokeAsync();
        }
        else if (Environment.GetEnvironmentVariable("KOHANE_STATION_SMOKE_CAPS") == "1")
        {
            App.Trace("smoke: opening the capability directory");
            _ = ShowCapabilitiesAsync();
        }
    }

    private async Task RunSmokeAsync()
    {
        await AnalyzeAsync();
        if (Environment.GetEnvironmentVariable("KOHANE_STATION_SMOKE_RECORD") == "1")
        {
            App.Trace("smoke: recording the analysed file");
            await RecordAsync();
            App.Trace("smoke: refreshing the index panel");
            SearchBox.Text = "station";
            await SearchAsync();
            App.Trace($"smoke: index panel says [{IndexStatus.Text}] with {ResultsList.Items.Count} row(s)");
        }
        if (Environment.GetEnvironmentVariable("KOHANE_STATION_SMOKE_CAPS") == "1")
        {
            await ShowCapabilitiesAsync();
            App.Trace($"smoke: capability panel says [{CapabilityStatus.Text}] with {CapabilityList.Items.Count} row(s)");
        }
    }

    // ---------- engine bridge helpers ----------

    private async Task<HttpResponseMessage> PostToolAsync(string name, object? args)
    {
        var body = JsonSerializer.Serialize(new { name, args });
        using var content = new StringContent(body, Encoding.UTF8, "application/json");
        return await _http.PostAsync($"{Bridge}/tools/call", content);
    }

    private async Task<JsonElement> PostToolJsonAsync(string name, object? args)
    {
        using var resp = await PostToolAsync(name, args);
        var text = await resp.Content.ReadAsStringAsync();
        return JsonSerializer.Deserialize<JsonElement>(text);
    }

    private async Task<string> GetBridgeAsync(string path) => await _http.GetStringAsync($"{Bridge}{path}");

    private Brush Res(string key) => (Brush)Application.Current.Resources[key];

    private static string Get(JsonElement e, string name, string fallback)
        => e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String
            ? v.GetString() ?? fallback
            : fallback;

    private static bool GetBool(JsonElement e, string name)
        => e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.True;

    private static string GetNumber(JsonElement e, string name)
        => e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number
            ? v.GetDouble().ToString("0.##", CultureInfo.InvariantCulture)
            : "";

    /// <summary>The engine reports the colours an editor's themes use; take them as given.</summary>
    private static Brush BrushFromHex(string? hex, string fallbackKey)
    {
        if (!string.IsNullOrWhiteSpace(hex))
        {
            var h = hex.TrimStart('#');
            if (h.Length == 6 &&
                byte.TryParse(h.Substring(0, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var r) &&
                byte.TryParse(h.Substring(2, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var g) &&
                byte.TryParse(h.Substring(4, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var b))
            {
                return new SolidColorBrush(Windows.UI.Color.FromArgb(255, r, g, b));
            }
        }
        return (Brush)Application.Current.Resources[fallbackKey];
    }

    private async Task InitEngineStatusAsync()
    {
        try
        {
            var list = await GetBridgeAsync("/tools/list");
            EngineStatus.Text = $"引擎: 已连接 · {CountTools(list)} 工具";
            EngineStatus.Foreground = Res("VerdictGoodBrush");
            EngineChip.Background = Res("VerdictGoodWashBrush");
        }
        catch
        {
            EngineStatus.Text = "引擎: 未连接 · 先起 engine-bridge/server.mjs";
            EngineStatus.Foreground = Res("VerdictWarnBrush");
            EngineChip.Background = Res("VerdictWarnWashBrush");
            SetMood("pout");
        }
    }

    private static long CountTools(string json)
    {
        // The bridge answers { "tools": [ ...names ] }, so the count lives one level down.
        try
        {
            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.TryGetProperty("tools", out var tools) && tools.ValueKind == JsonValueKind.Array)
                return tools.GetArrayLength();
            if (doc.RootElement.ValueKind == JsonValueKind.Array)
                return doc.RootElement.GetArrayLength();
            return 0;
        }
        catch { return 0; }
    }

    // ---------- her faces ----------

    /// <summary>
    /// Her moods, split from the two Q sheets by tools/make-assets.ps1. Which one she wears is
    /// decided by the file's working-tree state - the character reports the status, the same way the
    /// character in an editor's disk utility edition reports a drive's health.
    /// </summary>
    private static readonly Dictionary<string, (string File, string Line)> Moods = new()
    {
        ["idle"] = ("kohane-q-idle", "湯に浸かりながら待っておるよ"),
        ["bankai"] = ("kohane-ultra-q-bankai", "卍解 · 山丹"),
        ["happy"] = ("kohane-q-happy", "よし、識別できたよ"),
        ["thinking"] = ("kohane-q-thinking", "ううん、見たことのない形だ……"),
        ["panic"] = ("kohane-q-panic", "えっ、名札と中身が違う……"),
        ["pout"] = ("kohane-ultra-q-pout", "む……橋が繋がってないよ"),
        ["calm"] = ("kohane-q-calm", "図鑑に書き留めておいたよ"),
        ["sleepy"] = ("kohane-q-sleepy", "図鑑はまだ空っぽだよ"),
        ["ready"] = ("kohane-q-ready", "いつでもどうぞ"),
        ["shy"] = ("kohane-q-shy", "えっと……見ないでよ"),
        ["composed"] = ("kohane-q-composed", "ここは任せておくれ"),
    };

    private void SetMood(string mood)
    {
        if (!Moods.TryGetValue(mood, out var entry)) entry = Moods["calm"];
        try
        {
            var brush = (ImageBrush)AvatarBox.Background;
            brush.ImageSource = new BitmapImage(new Uri($"ms-appx:///Assets/{entry.File}.png"));
        }
        catch (Exception ex)
        {
            App.Trace("mood: could not set " + mood + " - " + ex.Message);
        }
        MoodLine.Text = entry.Line;
    }

    /// <summary>
    /// A working-tree state, as her: the badge an editor paints plus the face she pulls for it.
    /// </summary>
    private sealed record VcsLook(string Letter, string Label, string Mood, string Line, string BrushKey);

    private static readonly Dictionary<string, VcsLook> VcsLooks = new()
    {
        ["M"] = new("M", "已修改", "composed", "这里动过了呢", "VerdictWarnBrush"),
        ["A"] = new("A", "新增（已暂存）", "ready", "已经收好了", "VerdictGoodBrush"),
        ["D"] = new("D", "已删除", "panic", "咦，它不见了……", "VerdictBadBrush"),
        ["R"] = new("R", "已改名", "thinking", "换了个名字呀", "VerdictGoodBrush"),
        ["C"] = new("C", "已复制", "thinking", "多了一份呢", "VerdictGoodBrush"),
        ["T"] = new("T", "类型变更", "thinking", "它的性子变了", "VerdictWarnBrush"),
        ["U"] = new("U", "未跟踪", "happy", "新面孔，先记下来", "VerdictGoodBrush"),
        ["I"] = new("I", "已忽略", "sleepy", "它被忽略了，不必管", "VerdictIdleBrush"),
        ["!"] = new("!", "冲突未解", "bankai", "这里打起来了呢", "VerdictBadBrush"),
        ["S"] = new("S", "子模块有变", "thinking", "里面的小仓库动了", "VerdictWarnBrush"),
        ["clean"] = new("—", "已提交", "calm", "安安静静的", "VerdictIdleBrush"),
        ["none"] = new("—", "不在仓库中", "idle", "仓库之外，随它吧", "VerdictIdleBrush"),
    };

    /// <summary>Not one of the states an editor names: keep the engine's own words.</summary>
    private static VcsLook LookOf(JsonElement vcs)
    {
        var state = Get(vcs, "state", "none");
        if (VcsLooks.TryGetValue(state, out var look)) return look;
        return new VcsLook(Get(vcs, "letter", "—"), Get(vcs, "label", state), "thinking", "ちょっと見てみよう", "VerdictWarnBrush");
    }

    // ---------- verdict + status boxes ----------

    private void SetVerdict(string kind, string mark, string word, string format)
    {
        var fg = kind switch
        {
            "good" => "VerdictGoodBrush",
            "warn" => "VerdictWarnBrush",
            "bad" => "VerdictBadBrush",
            _ => "VerdictIdleBrush",
        };
        VerdictMark.Text = mark;
        VerdictMark.Foreground = Res(fg);
        VerdictText.Text = word;
        VerdictText.Foreground = Res(fg);
        VerdictFormat.Text = format;
    }

    /// <summary>The crimson wash of her 卍解: the card itself warns when the find is sensitive.</summary>
    private void TintAnalyzerCard(bool alarmed)
    {
        AnalyzerCard.Background = Res(alarmed ? "VerdictBadWashBrush" : "CardBrush");
        AnalyzerCard.BorderBrush = Res(alarmed ? "KohaneCrimsonBrush" : "CardStrokeBrush");
        AnalyzerCard.BorderThickness = new Thickness(alarmed ? 2 : 1);
    }

    /// <summary>
    /// DiskInfo lays a drive's information out in two columns; splitting the rows here keeps a dozen
    /// attributes visible without scrolling.
    /// </summary>
    private void SetPropRows(List<PropRow> rows)
    {
        var half = (rows.Count + 1) / 2;
        PropList.ItemsSource = rows.GetRange(0, half);
        PropList2.ItemsSource = rows.GetRange(half, rows.Count - half);
    }

    private void ShowIdleTable()
    {
        SetVerdict("idle", "—", "等待取件", "—");
        SetMood("sleepy");
        TintAnalyzerCard(false);
        SetVcsBadge(null);
        RepoStatus.Text = "仓库: —";
        SetPropRows(new List<PropRow>
        {
            new() { Label = "路径", Value = "（尚未选择文件）" },
            new() { Label = "提示", Value = "拖入文件、用「浏览…」选择，或粘贴路径后按「识读」" },
        });
        RecordBtn.Visibility = Visibility.Collapsed;
    }

    private void SetVcsBadge(JsonElement? vcs)
    {
        if (vcs is null)
        {
            VcsBadge.Text = "—";
            VcsBadge.Foreground = Res("VerdictIdleBrush");
            ToolTipService.SetToolTip(VcsBadge, null);
            return;
        }
        var look = LookOf(vcs.Value);
        VcsBadge.Text = look.Letter;
        VcsBadge.Foreground = Res(look.BrushKey);
        ToolTipService.SetToolTip(VcsBadge, look.Label);
    }

    // ---------- working-tree state ----------

    /// <summary>
    /// Ask the engine for the file's working-tree state, then let her report it: the badge beside the
    /// format, the chip in the header, and the face in the corner. A path outside a repository or a
    /// machine without git is answered, not failed, so this never blocks an analysis.
    /// </summary>
    private async Task<JsonElement?> AskVcsAsync(string path)
    {
        try
        {
            var vcs = await PostToolJsonAsync("library_vcs", new { op = "status", path });
            if (vcs.ValueKind != JsonValueKind.Object) return null;

            // A bridge running an older engine answers 404 with a JSON error body. Without this guard
            // that body reads as "no state", which quietly looks like "not in a repository".
            if (!vcs.TryGetProperty("state", out _))
            {
                var why = Get(vcs, "error", "the bridge did not answer with a state");
                App.Trace("vcs: bridge gave no state - " + why);
                SetVcsBadge(null);
                RepoStatus.Text = "仓库: 桥未提供 library_vcs";
                return null;
            }

            _lastVcs = vcs;
            SetVcsBadge(vcs);

            var state = Get(vcs, "state", "none");
            var repo = Get(vcs, "repo", "");
            var branch = vcs.TryGetProperty("branch", out var b) && b.ValueKind == JsonValueKind.Object ? Get(b, "name", "") : "";
            RepoStatus.Text = string.IsNullOrEmpty(repo)
                ? $"仓库: {Get(vcs, "label", "不在仓库中")}"
                : $"仓库: {System.IO.Path.GetFileName(repo.TrimEnd('\\', '/'))}{(string.IsNullOrEmpty(branch) ? "" : " · " + branch)}";
            App.Trace($"vcs: state={state} letter={Get(vcs, "letter", "-")} repo={(repo.Length > 0 ? "yes" : "no")}");
            return vcs;
        }
        catch (Exception ex)
        {
            App.Trace("vcs: FAILED - " + ex.Message);
            SetVcsBadge(null);
            RepoStatus.Text = "仓库: 未知（桥未连接）";
            return null;
        }
    }

    // ---------- instant analyzer ----------

    private async void OnBrowseClick(object sender, RoutedEventArgs e)
    {
        var picker = new FileOpenPicker();
        picker.FileTypeFilter.Add("*");

        var hwnd = WindowNative.GetWindowHandle(this);
        InitializeWithWindow.Initialize(picker, hwnd);

        StorageFile? file = await picker.PickSingleFileAsync();
        if (file is not null)
        {
            PathBox.Text = file.Path;
            await AnalyzeAsync();
        }
    }

    private void OnAnalyzerDragOver(object sender, DragEventArgs e)
    {
        if (e.DataView.Contains(StandardDataFormats.StorageItems))
            e.AcceptedOperation = DataPackageOperation.Copy;
    }

    private async void OnAnalyzerDrop(object sender, DragEventArgs e)
    {
        if (e.DataView.Contains(StandardDataFormats.StorageItems))
        {
            var items = await e.DataView.GetStorageItemsAsync();
            if (items.Count > 0 && items[0] is StorageFile file)
            {
                PathBox.Text = file.Path;
                await AnalyzeAsync();
            }
        }
    }

    private async void OnAnalyzeClick(object sender, RoutedEventArgs e) => await AnalyzeAsync();

    private async Task AnalyzeAsync()
    {
        var path = PathBox.Text?.Trim();
        if (string.IsNullOrEmpty(path))
        {
            ShowIdleTable();
            AnalyzerHint.Text = "请给出一条文件路径。";
            return;
        }

        SetVerdict("idle", "…", "识读中", "…");
        SetMood("bankai");
        TintAnalyzerCard(false);
        SetPropRows(new List<PropRow> { new() { Label = "路径", Value = path } });
        RecordBtn.Visibility = Visibility.Collapsed;
        AnalyzerHint.Text = "正在请引擎读取魔数与工作区状态…";
        App.Trace("analyze: asking the bridge about " + path);

        try
        {
            var sniff = await PostToolJsonAsync("library_sniff", new { path });
            _lastResult = sniff;

            var detected = sniff.TryGetProperty("detected", out var d) && d.GetBoolean();
            var type = Get(sniff, "type", "?");
            var format = Get(sniff, "format", "?");
            var note = Get(sniff, "note", "");
            var declared = Get(sniff, "declared", "");
            var spoofed = GetBool(sniff, "spoofed");
            var sensitive = GetBool(sniff, "sensitive");
            var temp = GetBool(sniff, "temp");
            var kind = Get(sniff, "kind", "");
            var artifact = Get(sniff, "artifact", "");
            var artifactNote = Get(sniff, "artifactNote", "");
            var flags = JoinFlags(sniff);

            // the working-tree state, asked in the same breath as the magic bytes
            var vcs = await AskVcsAsync(path);
            var inRepo = vcs is not null && Get(vcs.Value, "state", "none") != "none";
            var look = vcs is not null ? LookOf(vcs.Value) : null;

            if (sensitive)
            {
                SetVerdict("bad", "!", "注意 · 敏感路径", format);
                SetMood("bankai");
                TintAnalyzerCard(true);
            }
            else if (inRepo && look is not null)
            {
                // her face reports the file's state, which is what this workstation is for
                SetVerdict(spoofed ? "warn" : detected ? "good" : "warn",
                    spoofed ? "?" : detected ? "OK" : "?",
                    spoofed ? "名实不符" : detected ? "已识别" : "未匹配签名", format);
                SetMood(look.Mood);
                MoodLine.Text = look.Line;
                TintAnalyzerCard(false);
            }
            else if (spoofed)
            {
                SetVerdict("warn", "?", "名实不符", format);
                SetMood("panic");
                TintAnalyzerCard(false);
            }
            else if (detected)
            {
                SetVerdict("good", "OK", "已识别", format);
                SetMood("happy");
                TintAnalyzerCard(false);
            }
            else
            {
                SetVerdict("warn", "?", "未匹配签名", format);
                SetMood("thinking");
                TintAnalyzerCard(false);
            }

            SetPropRows(BuildRows(path, sniff, vcs, type, format, note, declared, spoofed, sensitive, temp, kind, artifact, artifactNote, flags));
            RecordBtn.Visibility = Visibility.Visible;
            AnalyzerHint.Text = "识别完成 — 可写入图鉴";

            // a score is the one file kind the waterfall can show, so opening it opens the panel
            var scoreExt = Path.GetExtension(path).ToLowerInvariant();
            if (scoreExt is ".mid" or ".midi") await LoadWaterfallAsync(path);
            App.Trace($"analyze: done - detected={detected} type={type} format={format}");
        }
        catch (Exception ex)
        {
            SetVerdict("bad", "!", "识读失败", "—");
            SetMood("pout");
            TintAnalyzerCard(false);
            SetVcsBadge(null);
            SetPropRows(new List<PropRow>
            {
                new() { Label = "路径", Value = path },
                new() { Label = "错误", Value = ex.Message },
            });
            AnalyzerHint.Text = "桥接未连接时无法识读 — 先启动 engine-bridge/server.mjs";
            App.Trace("analyze: FAILED - " + ex.GetType().Name + ": " + ex.Message);
        }
    }

    /// <summary>
    /// The property table, ordered the way DiskInfo orders a drive: what it is, where it is, the
    /// measurements - and now, with the engine's working-tree answer, what has happened to it.
    /// </summary>
    private static List<PropRow> BuildRows(
        string path, JsonElement sniff, JsonElement? vcs, string type, string format, string note, string declared,
        bool spoofed, bool sensitive, bool temp, string kind, string artifact, string artifactNote, string flags)
    {
        var rows = new List<PropRow> { new() { Label = "路径", Value = path } };

        try
        {
            var info = new FileInfo(path);
            if (info.Exists)
            {
                rows.Add(new PropRow { Label = "文件名", Value = info.Name });
                rows.Add(new PropRow { Label = "所在目录", Value = info.DirectoryName ?? "?" });
                rows.Add(new PropRow { Label = "大小", Value = $"{FormatSize(info.Length)}  ({info.Length:N0} 字节)" });
                rows.Add(new PropRow { Label = "修改时间", Value = info.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) });
                rows.Add(new PropRow { Label = "创建时间", Value = info.CreationTime.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) });
            }
            else
            {
                rows.Add(new PropRow { Label = "文件状态", Value = "路径不存在或不可读（仅按扩展名判断）" });
            }
        }
        catch (Exception ex)
        {
            rows.Add(new PropRow { Label = "文件状态", Value = "无法读取: " + ex.Message });
        }

        rows.Add(new PropRow { Label = "扩展名", Value = string.IsNullOrEmpty(System.IO.Path.GetExtension(path)) ? "（无）" : System.IO.Path.GetExtension(path) });
        rows.Add(new PropRow { Label = "声明类型", Value = string.IsNullOrEmpty(declared) ? "（无）" : declared });
        rows.Add(new PropRow { Label = "真实类型", Value = type });
        rows.Add(new PropRow { Label = "格式", Value = format });
        rows.Add(new PropRow { Label = "种类", Value = string.IsNullOrEmpty(kind) ? "?" : kind + (temp ? "  ·  临时文件" : "") });
        rows.Add(new PropRow { Label = "名实相符", Value = spoofed ? "不符 — 扩展名与内容矛盾" : "相符" });
        rows.Add(new PropRow { Label = "敏感", Value = sensitive ? "是（记录时会加密）" : "否" });
        if (!string.IsNullOrEmpty(note)) rows.Add(new PropRow { Label = "说明", Value = note });
        if (!string.IsNullOrEmpty(artifact)) rows.Add(new PropRow { Label = "归属格式族", Value = artifact });
        if (!string.IsNullOrEmpty(artifactNote)) rows.Add(new PropRow { Label = "族说明", Value = artifactNote });
        if (!string.IsNullOrEmpty(flags)) rows.Add(new PropRow { Label = "特征", Value = flags });

        if (vcs is not null)
        {
            var v = vcs.Value;
            var look = LookOf(v);
            rows.Add(new PropRow { Label = "版本状态", Value = look.Letter == "—" ? look.Label : $"{look.Letter}  {look.Label}" });
            var staged = GetBool(v, "staged");
            var unstaged = GetBool(v, "unstaged");
            var sides = new List<string>();
            if (staged) sides.Add("已暂存");
            if (unstaged) sides.Add("工作区");
            rows.Add(new PropRow { Label = "改动所在", Value = sides.Count > 0 ? string.Join(" + ", sides) : "—" });

            var counts = new List<string>();
            var a = GetNumber(v, "added");
            var del = GetNumber(v, "deleted");
            if (a.Length > 0 || del.Length > 0) counts.Add($"工作区 +{a} / -{del}");
            var sa = GetNumber(v, "stagedAdded");
            var sd = GetNumber(v, "stagedDeleted");
            if (sa.Length > 0 || sd.Length > 0) counts.Add($"暂存 +{sa} / -{sd}");
            rows.Add(new PropRow { Label = "增删行数", Value = counts.Count > 0 ? string.Join("；", counts) : "—" });

            var orig = Get(v, "origPath", "");
            if (!string.IsNullOrEmpty(orig)) rows.Add(new PropRow { Label = "原路径", Value = orig });
            var rel = Get(v, "relative", "");
            if (!string.IsNullOrEmpty(rel)) rows.Add(new PropRow { Label = "仓库内路径", Value = rel });

            var repo = Get(v, "repo", "");
            if (!string.IsNullOrEmpty(repo))
            {
                var branch = v.TryGetProperty("branch", out var b) && b.ValueKind == JsonValueKind.Object ? Get(b, "name", "") : "";
                var ahead = b.ValueKind == JsonValueKind.Object ? GetNumber(b, "ahead") : "";
                var behind = b.ValueKind == JsonValueKind.Object ? GetNumber(b, "behind") : "";
                var bits = new List<string>();
                if (!string.IsNullOrEmpty(branch)) bits.Add(branch);
                if (ahead.Length > 0 && ahead != "0") bits.Add($"领先 {ahead}");
                if (behind.Length > 0 && behind != "0") bits.Add($"落后 {behind}");
                rows.Add(new PropRow { Label = "分支", Value = bits.Count > 0 ? string.Join(" · ", bits) : "—" });
                rows.Add(new PropRow { Label = "仓库根", Value = repo });
            }

            var git = Get(v, "git", "");
            if (!string.IsNullOrEmpty(git)) rows.Add(new PropRow { Label = "git", Value = git });
        }

        return rows;
    }

    private static string JoinFlags(JsonElement e)
    {
        if (!e.TryGetProperty("flags", out var f) || f.ValueKind != JsonValueKind.Array) return "";
        var parts = new List<string>();
        foreach (var item in f.EnumerateArray())
            if (item.ValueKind == JsonValueKind.String) parts.Add(item.GetString() ?? "");
        return string.Join(" · ", parts);
    }

    private static string FormatSize(long bytes)
    {
        string[] units = { "B", "KB", "MB", "GB", "TB" };
        double size = bytes;
        var unit = 0;
        while (size >= 1024 && unit < units.Length - 1) { size /= 1024; unit++; }
        return unit == 0 ? $"{bytes} B" : $"{size:0.##} {units[unit]}";
    }

    private async void OnRecordClick(object sender, RoutedEventArgs e) => await RecordAsync();

    /// <summary>Write the analysed file into the Library, then refresh the index panel.</summary>
    private async Task RecordAsync()
    {
        var path = PathBox.Text?.Trim();
        if (string.IsNullOrEmpty(path) || _lastResult is null) return;

        try
        {
            var format = _lastResult?.TryGetProperty("format", out var f) == true ? f.GetString() ?? "file" : "file";
            var type = _lastResult?.TryGetProperty("type", out var t) == true ? t.GetString() ?? "other" : "other";
            var name = System.IO.Path.GetFileName(path);

            var tags = new List<string> { "station", format };
            if (_lastVcs is not null)
            {
                var state = Get(_lastVcs.Value, "state", "");
                if (!string.IsNullOrEmpty(state) && state != "none") tags.Add("vcs-" + state);
            }

            var args = new
            {
                type,
                name,
                source = "kohane-station",
                path,
                description = $"recorded from Kohane workstation (engine-identified {format})",
                tags = tags.ToArray(),
            };

            var rec = await PostToolJsonAsync("library_record", args);
            var ok = rec.TryGetProperty("ok", out var k) && k.GetBoolean();
            AnalyzerHint.Text = ok ? "已写入图鉴 — 右栏可检索到" : "写入需要确认";
            if (ok) SetMood("calm");
            App.Trace($"record: ok={ok} name={name} type={type}");
            await SearchAsync();
        }
        catch (Exception ex)
        {
            AnalyzerHint.Text = "写入失败: " + ex.Message;
            App.Trace("record: FAILED - " + ex.Message);
        }
    }

    // ---------- library view ----------

    private async void OnSearchClick(object sender, RoutedEventArgs e) => await SearchAsync();

    private async void OnSearchKeyDown(object sender, KeyRoutedEventArgs e)
    {
        if (e.Key == Windows.System.VirtualKey.Enter) await SearchAsync();
    }

    private async Task SearchAsync()
    {
        var q = SearchBox.Text?.Trim();
        var args = new Dictionary<string, object> { ["limit"] = 200 };
        if (!string.IsNullOrEmpty(q)) args["query"] = q;

        try
        {
            var res = await PostToolJsonAsync("library_query", args);
            var results = res.GetProperty("results");
            var count = res.GetProperty("count").GetInt32();

            var rows = new List<IndexRow>();
            foreach (var o in results.EnumerateArray())
            {
                rows.Add(new IndexRow
                {
                    Kind = Get(o, "type", ""),
                    Name = Get(o, "name", "?"),
                    Source = Get(o, "source", ""),
                    Path = Get(o, "path", ""),
                });
            }

            await DecorateAsync(rows);
            ResultsList.ItemsSource = rows;

            IndexStatus.Text = count == 0
                ? "图鉴为空 — 先识读并写入，或换个检索词"
                : $"收录 {count} 条" + (rows.Count < count ? $"（显示前 {rows.Count} 条）" : "");
        }
        catch (Exception ex)
        {
            IndexStatus.Text = "检索失败: " + ex.Message;
        }
    }

    /// <summary>
    /// Decorate a whole list in one call: the engine groups the paths by repository, so a hundred rows
    /// cost one git call rather than a hundred. The colour comes from the engine too.
    /// </summary>
    private async Task DecorateAsync(List<IndexRow> rows)
    {
        var paths = rows.Where((r) => !string.IsNullOrEmpty(r.Path)).Select((r) => r.Path).Distinct().ToList();
        foreach (var r in rows) r.StatusBrush = Res("VerdictIdleBrush");
        if (paths.Count == 0) return;

        try
        {
            var deco = await PostToolJsonAsync("library_vcs", new { op = "decorate", paths });
            if (!deco.TryGetProperty("items", out var items) || items.ValueKind != JsonValueKind.Array) return;

            var byPath = new Dictionary<string, JsonElement>(StringComparer.OrdinalIgnoreCase);
            foreach (var item in items.EnumerateArray())
            {
                var p = Get(item, "path", "");
                if (!string.IsNullOrEmpty(p)) byPath[p] = item;
            }

            foreach (var r in rows)
            {
                if (string.IsNullOrEmpty(r.Path) || !byPath.TryGetValue(r.Path, out var item)) continue;
                var look = LookOf(item);
                r.StatusLetter = look.Letter;
                r.StatusBrush = Res(look.BrushKey);
            }
            App.Trace($"vcs: decorated {byPath.Count} path(s) for the index list");
        }
        catch (Exception ex)
        {
            App.Trace("vcs: decorate failed - " + ex.Message);
        }
    }

    // ---------- capability view ----------

    // ---------- waterfall view ----------
    //
    // The panel is created in code and added to its host grid: that keeps the control free of any
    // xmlns mapping here, and an unwired tab costs nothing until it is first opened.

    private void OnShowWaterfallClick(object sender, RoutedEventArgs e) => ShowWaterfall();

    private void ShowWaterfall()
    {
        _waterfall ??= new WaterfallView();
        if (WaterfallHost.Children.Count == 0) WaterfallHost.Children.Add(_waterfall);
        LibraryView.Visibility = Visibility.Collapsed;
        CapabilityView.Visibility = Visibility.Collapsed;
        WaterfallHost.Visibility = Visibility.Visible;
        LibraryTab.Style = (Style)Application.Current.Resources["TabOffButton"];
        CapabilityTab.Style = (Style)Application.Current.Resources["TabOffButton"];
        WaterfallTab.Style = (Style)Application.Current.Resources["TabOnButton"];
    }

    /// <summary>
    /// Reads a score through the engine's own reader (library_audio op=score) and starts it falling.
    /// The engine is the only thing that parses the file: the shell never grows a second MIDI reader,
    /// because two readers eventually disagree about what the file says.
    /// </summary>
    private async Task LoadWaterfallAsync(string path)
    {
        try
        {
            var score = await PostToolJsonAsync("library_audio", new { op = "score", path });
            if (score.TryGetProperty("ok", out var ok) && ok.ValueKind == JsonValueKind.True)
            {
                _waterfall ??= new WaterfallView();
                if (WaterfallHost.Children.Count == 0) WaterfallHost.Children.Add(_waterfall);
                _waterfall.LoadScore(score.GetRawText());
                ShowWaterfall();
                _waterfall.Start();
                App.Trace($"waterfall: loaded {path}");
            }
            else
            {
                App.Trace($"waterfall: engine refused {path}");
            }
        }
        catch (Exception ex)
        {
            App.Trace($"waterfall: failed {path} - {ex.Message}");
        }
    }

    private void OnShowLibraryClick(object sender, RoutedEventArgs e)
    {
        LibraryView.Visibility = Visibility.Visible;
        CapabilityView.Visibility = Visibility.Collapsed;
        WaterfallHost.Visibility = Visibility.Collapsed;
        LibraryTab.Style = (Style)Application.Current.Resources["TabOnButton"];
        CapabilityTab.Style = (Style)Application.Current.Resources["TabOffButton"];
        WaterfallTab.Style = (Style)Application.Current.Resources["TabOffButton"];
    }

    private async void OnShowCapabilityClick(object sender, RoutedEventArgs e) => await ShowCapabilitiesAsync();

    private async void OnCapabilityRefreshClick(object sender, RoutedEventArgs e) => await LoadCapabilitiesAsync();

    private async void OnCapabilityKeyDown(object sender, KeyRoutedEventArgs e)
    {
        if (e.Key == Windows.System.VirtualKey.Enter) await LoadCapabilitiesAsync();
    }

    private async Task ShowCapabilitiesAsync()
    {
        LibraryView.Visibility = Visibility.Collapsed;
        CapabilityView.Visibility = Visibility.Visible;
        WaterfallHost.Visibility = Visibility.Collapsed;
        LibraryTab.Style = (Style)Application.Current.Resources["TabOffButton"];
        CapabilityTab.Style = (Style)Application.Current.Resources["TabOnButton"];
        WaterfallTab.Style = (Style)Application.Current.Resources["TabOffButton"];
        if (!_capabilitiesLoaded) await LoadCapabilitiesAsync();
    }

    /// <summary>
    /// kohane's own capability directory: every capability it has adopted lives under one brand, and
    /// no third-party product name appears here.
    /// </summary>
    private async Task LoadCapabilitiesAsync()
    {
        CapabilityStatus.Text = "正在读取能力目录…";
        try
        {
            var res = await PostToolJsonAsync("library_plugin", new { op = "list" });
            if (!res.TryGetProperty("entries", out var entries) || entries.ValueKind != JsonValueKind.Array)
            {
                CapabilityStatus.Text = "能力目录为空 — 先跑一次 library_plugin op=discover/learn";
                return;
            }

            var filter = CapabilitySearch.Text?.Trim() ?? "";
            var rows = new List<CapRow>();
            foreach (var e in entries.EnumerateArray())
            {
                var name = Get(e, "name", "?");
                var role = Get(e, "role", "");
                if (filter.Length > 0 &&
                    name.IndexOf(filter, StringComparison.OrdinalIgnoreCase) < 0 &&
                    role.IndexOf(filter, StringComparison.OrdinalIgnoreCase) < 0) continue;

                var link = "—";
                if (e.TryGetProperty("linked", out var l))
                {
                    if (l.ValueKind == JsonValueKind.Number) link = l.GetInt32() > 0 ? $"已挂接 {l.GetInt32()}" : "—";
                    else if (l.ValueKind == JsonValueKind.String) link = l.GetString() ?? "—";
                }
                rows.Add(new CapRow { Name = name, Role = role, Link = link });
            }

            CapabilityList.ItemsSource = rows;
            var total = res.TryGetProperty("total", out var t) ? t.GetInt32() : rows.Count;
            var linked = res.TryGetProperty("linked", out var lk) ? lk.GetInt32() : 0;
            var unlinked = res.TryGetProperty("unlinked", out var ul) && ul.ValueKind == JsonValueKind.Number ? ul.GetInt32() : Math.Max(total - linked, 0);
            var brand = res.TryGetProperty("brand", out var br) ? br.GetString() ?? "Kohane Bassline" : "Kohane Bassline";
            CapabilityStatus.Text = $"{brand} · 共 {total} 项 · 已挂接 {linked} · 未挂接 {unlinked}" + (filter.Length > 0 ? $"（筛出 {rows.Count}）" : "");
            _capabilitiesLoaded = true;
            App.Trace($"capabilities: {rows.Count} row(s) shown, total {total}, linked {linked}");
        }
        catch (Exception ex)
        {
            CapabilityStatus.Text = "能力目录读取失败: " + ex.Message;
            App.Trace("capabilities: FAILED - " + ex.Message);
        }
    }
}
