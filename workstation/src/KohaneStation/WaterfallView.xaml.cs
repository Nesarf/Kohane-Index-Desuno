using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Threading.Tasks;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media.Imaging;
using Windows.UI;

namespace KohaneStation;

/// <summary>
/// The falling-note panel, in the idiom that falling-note players established: x is time (flowing left as the playhead
/// advances), y is pitch, a block's width is its duration, and a block brightens while it sounds.
///
/// It renders by writing pixels into a <see cref="WriteableBitmap"/> rather than composing thousands of
/// XAML elements - a long piece is tens of thousands of notes, and an element per note would be a
/// layout storm with no benefit. Everything is culled to the visible window before it is drawn, so cost
/// follows what is on screen rather than how long the piece is.
/// </summary>
public sealed partial class WaterfallView : UserControl
{
    private sealed class Note
    {
        public double Tick;
        public double Ticks;
        public int Key;
        public int Velocity;
        public int Channel;
        public int Track;
        public bool IsDrum;
    }

    private sealed class TrackInfo
    {
        public string Name = "";
        public Color Face;
    }

    private readonly List<Note> _notes = new();
    private readonly List<TrackInfo> _tracks = new();
    private double _ppq = 96;
    private double _tempo = 120;
    private double _lastTick;
    private double _playhead;                 // in ticks
    private int _lowestKey = 21;              // piano range, widened to the piece's own range on load
    private int _highestKey = 108;
    private WriteableBitmap? _bitmap;
    private readonly DispatcherTimer _timer = new();
    private double _secondsPerTick = 0.5 / 96.0;

    // One colour per track, in the theme's own family: crimson leads, tea and navy support, and the
    // drums get a warmer tone so a rhythm track reads at a glance.
    private static readonly uint[] Palette =
    {
        0xFF3028A8, 0xFF487830, 0xFF888AE0, 0xFF4F7D2E, 0xFF1E8AC0, 0xFFFFFFFF,
        0xFF404870, 0xFF3038A8, 0xFF8E60C0, 0xFF4020A8, 0xFF907040, 0xFF303848,
    };

    public WaterfallView()
    {
        InitializeComponent();
        Surface.SizeChanged += (_, _) => Allocate();
        Loaded += (_, _) => Allocate();
        _timer.Interval = TimeSpan.FromMilliseconds(16);
        _timer.Tick += (_, _) => Advance();
    }

    /// <summary>Loads a score as returned by the engine's library_audio op=score.</summary>
    public void LoadScore(string json)
    {
        _notes.Clear();
        _tracks.Clear();

        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        _ppq = root.TryGetProperty("ppq", out var ppq) && ppq.ValueKind == JsonValueKind.Number ? ppq.GetDouble() : 96;
        _tempo = root.TryGetProperty("tempo", out var tempo) && tempo.ValueKind == JsonValueKind.Number ? tempo.GetDouble() : 120;
        _lastTick = root.TryGetProperty("lastTick", out var last) && last.ValueKind == JsonValueKind.Number ? last.GetDouble() : 0;
        _secondsPerTick = _tempo > 0 ? 60.0 / (_tempo * _ppq) : 0.005;

        var title = root.TryGetProperty("title", out var t) && t.ValueKind == JsonValueKind.String ? t.GetString() ?? "" : "";
        var tracks = root.GetProperty("tracks");

        var index = 0;
        foreach (var track in tracks.EnumerateArray())
        {
            var info = new TrackInfo
            {
                Name = track.TryGetProperty("name", out var n) && n.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(n.GetString())
                    ? n.GetString()!
                    : $"声部 {index + 1}",
                Face = FromArgb(Palette[index % Palette.Length]),
            };
            _tracks.Add(info);

            if (track.TryGetProperty("notes", out var notes) && notes.ValueKind == JsonValueKind.Array)
            {
                foreach (var note in notes.EnumerateArray())
                {
                    var key = note.GetProperty("note").GetInt32();
                    _notes.Add(new Note
                    {
                        Tick = note.GetProperty("tick").GetDouble(),
                        Ticks = Math.Max(1, note.GetProperty("ticks").GetDouble()),
                        Key = key,
                        Velocity = note.TryGetProperty("velocity", out var v) ? v.GetInt32() : 96,
                        Channel = note.TryGetProperty("channel", out var c) ? c.GetInt32() : 0,
                        Track = index,
                        IsDrum = (note.TryGetProperty("channel", out var dc) ? dc.GetInt32() : 0) == 9,
                    });
                }
            }
            index++;
        }

        _playhead = 0;
        if (_notes.Count > 0)
        {
            _lowestKey = Math.Max(0, _notes.Min(x => x.Key) - 2);
            _highestKey = Math.Min(127, _notes.Max(x => x.Key) + 2);
        }

        var seconds = _lastTick * _secondsPerTick;
        ScoreLine.Text = $"瀑布 · {title} · {_tracks.Count} 声部 · {_notes.Count} 音符 · {TimeSpan.FromSeconds(seconds):m\\:ss}";
        ScaleLine.Text = $"{KeyName(_lowestKey)}..{KeyName(_highestKey)} · {_tempo:0} BPM";
        Allocate();
        Draw();
    }

    public void Start() { _timer.Start(); PlayButton.Content = "暂停"; }
    public void Stop() { _timer.Stop(); PlayButton.Content = "落下"; }

    private void OnPlayClick(object sender, RoutedEventArgs e)
    {
        if (_timer.IsEnabled) Stop(); else Start();
    }

    private void OnRewindClick(object sender, RoutedEventArgs e)
    {
        _playhead = 0;
        Draw();
    }

    private void Advance()
    {
        // 16 ms per frame is roughly 1/60 s of real time, so the playhead moves at the piece's tempo
        _playhead += 0.06 / _secondsPerTick;
        if (_playhead > _lastTick + _ppq * 4) { _playhead = 0; }
        Draw();
    }

    private void Allocate()
    {
        var w = (int)Math.Max(320, Surface.ActualWidth > 0 ? Surface.ActualWidth : ActualWidth - 20);
        var h = (int)Math.Max(180, (ActualHeight > 240 ? ActualHeight : 420) - 120);
        if (w <= 0 || h <= 0) return;
        if (_bitmap == null || _bitmap.PixelWidth != w || _bitmap.PixelHeight != h)
        {
            _bitmap = new WriteableBitmap(w, h);
            Surface.Source = _bitmap;
        }
    }

    private void Draw()
    {
        if (_bitmap == null) return;
        var w = _bitmap.PixelWidth;
        var h = _bitmap.PixelHeight;
        var pixels = new byte[w * h * 4];

        // background: the ink-dark surface of the panel, with faint octave lines so pitch is readable
        for (var i = 0; i < pixels.Length; i += 4)
        {
             pixels[i] = 0x16; pixels[i + 1] = 0x1A; pixels[i + 2] = 0x1E; pixels[i + 3] = 0xFF;
        }

        var keys = Math.Max(1, _highestKey - _lowestKey + 1);
        var keyHeight = (double)h / keys;
        var visibleTicks = _ppq * 8;                       // eight beats of look-ahead
        var pxPerTick = w / visibleTicks;

        // one bar of look-ahead on the right, a little history on the left
        var from = _playhead - _ppq * 1;
        var to = _playhead + visibleTicks;

        // octave rules
        for (var key = _lowestKey; key <= _highestKey; key++)
        {
            if (key % 12 != 0) continue;
            var y = (int)((_highestKey - key) * keyHeight);
            for (var x = 0; x < w; x++)
            {
                var o = (y * w + x) * 4;
                if (o + 3 < pixels.Length) { pixels[o] = 0x38; pixels[o + 1] = 0x40; pixels[o + 2] = 0x30; }
            }
        }

        foreach (var note in _notes)
        {
            if (note.Tick + note.Ticks < from || note.Tick > to) continue;   // culled: never drawn
            if (note.Key < _lowestKey || note.Key > _highestKey) continue;

            var x0 = (int)((note.Tick - from) * pxPerTick);
            var x1 = (int)((note.Tick + note.Ticks - from) * pxPerTick);
            var width = Math.Max(2, x1 - x0);
            var top = (int)((_highestKey - note.Key) * keyHeight);
            var height = Math.Max(2, (int)(keyHeight * 0.78));

            var face = _tracks[note.Track].Face;
            var sounding = _playhead >= note.Tick && _playhead < note.Tick + note.Ticks;
            var intensity = 0.55 + 0.45 * (note.Velocity / 127.0);
            if (sounding) intensity = Math.Min(1.0, intensity + 0.35);       // brighter while it sounds

            if (note.IsDrum)
            {
                Diamond(pixels, w, h, x0, top, width, height, face, intensity);
            }
            else
            {
                Rect(pixels, w, h, x0, top, width, height, face, intensity);
            }
        }

        using (var stream = _bitmap.PixelBuffer.AsStream())
        {
            stream.Write(pixels, 0, pixels.Length);
        }
        _bitmap.Invalidate();

        var bar = _ppq > 0 ? _playhead / (_ppq * 4) : 0;
        PositionLine.Text = $"小节 {bar:0.0} / {(_ppq > 0 ? _lastTick / (_ppq * 4) : 0):0.0} · {(int)(_playhead * _secondsPerTick / 60)}:{(_playhead * _secondsPerTick % 60):00.0}";
    }

    private static void Rect(byte[] px, int w, int h, int x, int y, int width, int height, Color face, double intensity)
    {
        for (var yy = Math.Max(0, y); yy < Math.Min(h, y + height); yy++)
        {
            var row = yy * w;
            for (var xx = Math.Max(0, x); xx < Math.Min(w, x + width); xx++)
            {
                var o = (row + xx) * 4;
                if (o + 3 >= px.Length) continue;
                px[o] = (byte)(face.B * intensity);
                px[o + 1] = (byte)(face.G * intensity);
                px[o + 2] = (byte)(face.R * intensity);
                px[o + 3] = 0xFF;
            }
        }
    }

    private static void Diamond(byte[] px, int w, int h, int x, int y, int width, int height, Color face, double intensity)
    {
        var cx = x + width / 2.0;
        var cy = y + height / 2.0;
        var rx = Math.Max(2, width / 2.0);
        var ry = Math.Max(2, height / 2.0);
        for (var yy = Math.Max(0, y); yy < Math.Min(h, y + height); yy++)
        {
            for (var xx = Math.Max(0, x); xx < Math.Min(w, x + width); xx++)
            {
                var dx = Math.Abs(xx - cx) / rx;
                var dy = Math.Abs(yy - cy) / ry;
                if (dx + dy > 1.0) continue;
                var o = (yy * w + xx) * 4;
                if (o + 3 >= px.Length) continue;
                px[o] = (byte)(face.B * intensity);
                px[o + 1] = (byte)(face.G * intensity);
                px[o + 2] = (byte)(face.R * intensity);
                px[o + 3] = 0xFF;
            }
        }
    }

    private static Color FromArgb(uint value) => Color.FromArgb(
        (byte)((value >> 24) & 0xFF), (byte)((value >> 16) & 0xFF), (byte)((value >> 8) & 0xFF), (byte)(value & 0xFF));

    private static string KeyName(int key)
    {
        string[] names = { "C", "C#", "D", "D#", "E", "F", "F#", "G", "G#", "A", "A#", "B" };
        return names[((key % 12) + 12) % 12] + (key / 12 - 1).ToString(CultureInfo.InvariantCulture);
    }
}
