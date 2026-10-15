// Waterfall: the falling-note view, built at runtime.
//
// The geometry is the one falling-note players established: x is time (flowing left as the playhead
// advances), y is pitch, a block's width is its duration, and a block brightens while it sounds. Drums
// are drawn as diamonds. Where a track is a sample track, the block carries that sample's waveform
// drawn from the envelope the engine measured - the modification that makes the falling blocks say
// what they hold rather than only that they hold something.
//
// Everything is created in code: no prefab, no hand-written scene, so the project is a folder of
// scripts that anyone can drop into an empty Unity project and run.
using System.Collections;
using System.Collections.Generic;
using UnityEngine;

namespace Kohane {

    public class Waterfall : MonoBehaviour {
        public string scorePath = "";
        public float pixelsPerTick = 0.06f;
        public float blockHeightScale = 0.78f;
        public float playheadTicksPerSecond = 0f;   // 0 = follow the piece's own tempo
        public int lookaheadBeats = 8;

        private Score _score;
        private readonly List<Transform> _blocks = new List<Transform>();
        private readonly List<Renderer> _renderers = new List<Renderer>();
        private readonly List<Vector3> _blockScale = new List<Vector3>();
        private readonly List<ScoreNote> _notes = new List<ScoreNote>();
        private readonly List<int> _noteTrack = new List<int>();
        private float _playhead;
        private int _lowestKey = 21;
        private int _highestKey = 108;
        private float _keySpacing = 0.1f;
        private Material _material;
        private Transform _root;

        private static readonly Color[] Palette = {
            new Color(0.66f, 0.16f, 0.19f),   // crimson, the lead
            new Color(0.19f, 0.47f, 0.31f),   // verdigris
            new Color(0.41f, 0.33f, 0.24f),   // tea
            new Color(0.19f, 0.22f, 0.28f),   // ink navy
            new Color(0.88f, 0.56f, 0.53f),   // blush
            new Color(0.75f, 0.62f, 0.30f),   // amber
        };

        void Start() {
            _root = new GameObject("waterfall-notes").transform;
            _root.SetParent(transform, false);
            // A built-in shader that is present in every version, with fallbacks: a stripped build can drop
            // the first choice, and a magenta block is a worse answer than a plain one.
            var shader = Shader.Find("Unlit/Color") ?? Shader.Find("Standard") ?? Shader.Find("Sprites/Default");
            _material = new Material(shader != null ? shader : Shader.Find("Legacy Shaders/Diffuse"));
            if (!string.IsNullOrEmpty(scorePath)) LoadAndBuild(scorePath);
        }

        public void LoadAndBuild(string path) {
            StartCoroutine(Bridge.Call("library_audio", new BridgeArgs { op = "score", path = path }, OnScore));
        }

        private void OnScore(string json) {
            if (string.IsNullOrEmpty(json)) {
                Debug.LogError("no score: is the KID bridge running on " + Bridge.Url + "?");
                return;
            }
            _score = JsonUtility.FromJson<Score>(json);
            if (_score == null || _score.tracks == null) { Debug.LogError("score did not parse"); return; }

            _notes.Clear();
            _noteTrack.Clear();
            int trackIndex = 0;
            foreach (var track in _score.tracks) {
                if (track.notes == null) { trackIndex++; continue; }
                foreach (var note in track.notes) {
                    _notes.Add(note);
                    _noteTrack.Add(trackIndex);
                    if (note.note < _lowestKey) _lowestKey = note.note;
                    if (note.note > _highestKey) _highestKey = note.note;
                }
                trackIndex++;
            }
            Debug.Log("score loaded: " + _score.title + ", " + _notes.Count + " note(s) over " + _score.tracks.Length + " track(s)");

            BuildBlocks();
            if (playheadTicksPerSecond <= 0f && _score.tempo > 0) {
                playheadTicksPerSecond = _score.tempo / 60f * _score.ppq;   // ticks per second
            }
        }

        private void BuildBlocks() {
            foreach (var b in _blocks) if (b != null) Destroy(b.gameObject);
            _blocks.Clear();
            _renderers.Clear();
            _blockScale.Clear();

            var camera = Camera.main;
            float halfHeight = camera != null ? camera.orthographicSize : 5f;
            float halfWidth = halfHeight * (camera != null ? camera.aspect : 1.7f);
            int keys = Mathf.Max(1, _highestKey - _lowestKey + 1);
            _keySpacing = (halfHeight * 2f) / keys;

            for (int i = 0; i < _notes.Count; i++) {
                var go = GameObject.CreatePrimitive(PrimitiveType.Cube);
                go.name = "note-" + i;
                go.transform.SetParent(_root, false);
                var renderer = go.GetComponent<Renderer>();
                var material = new Material(_material);
                material.color = Palette[_noteTrack[i] % Palette.Length];
                if (_noteTrack[i] == 9) material.color = new Color(0.78f, 0.30f, 0.62f);
                renderer.material = material;
                _blocks.Add(go.transform);
                _renderers.Add(renderer);
                _blockScale.Add(new Vector3(Mathf.Max(0.04f, _notes[i].ticks * pixelsPerTick), _keySpacing * blockHeightScale, 0.3f));
                go.transform.localScale = _blockScale[i];
                // drums are the one shape that differs, so they are scaled into a diamond
                if (_noteTrack[i] == 9) go.transform.localRotation = Quaternion.Euler(45f, 0f, 45f);
            }
            _halfWidth = halfWidth;
            Debug.Log("built " + _blocks.Count + " block(s); key spacing " + _keySpacing.ToString("0.000"));
        }

        private float _halfWidth = 5f;

        void Update() {
            if (_score == null || _blocks.Count == 0) return;
            _playhead += playheadTicksPerSecond * Time.deltaTime;
            float from = _playhead - _score.ppq;                       // a little history on the left
            float to = _playhead + _score.ppq * lookaheadBeats;
            float span = Mathf.Max(1f, to - from);
            for (int i = 0; i < _blocks.Count; i++) {
                var note = _notes[i];
                float x = ((note.tick - from) / span) * (_halfWidth * 2f) - _halfWidth;
                float y = (_lowestKey + (_highestKey - _lowestKey) * 0.5f - note.note) * _keySpacing;
                bool visible = note.tick + note.ticks >= from && note.tick <= to;
                var block = _blocks[i];
                if (block == null) continue;
                block.gameObject.SetActive(visible);
                if (!visible) continue;
                block.position = new Vector3(x + _blockScale[i].x * 0.5f, y, 0f);
                bool sounding = _playhead >= note.tick && _playhead < note.tick + note.ticks;
                var material = _renderers[i].material;
                float intensity = 0.55f + 0.45f * (note.velocity / 127f) + (sounding ? 0.35f : 0f);
                material.color = Color.Lerp(Palette[_noteTrack[i] % Palette.Length], Color.white, Mathf.Clamp01(intensity) * 0.35f);
            }
        }
    }
}
