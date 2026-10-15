// KohaneBridge: talk to KID's local bridge and read a score back.
//
// The bridge is the same one the WinUI shell uses: POST /tools/call with {"name":..., "args":{...}}.
// Nothing here knows about audio formats - it asks the engine for notes and gets JSON, which is the
// point of having the engine in the first place.
using System.Collections;
using System.Text;
using UnityEngine;
using UnityEngine.Networking;

namespace Kohane {

    [System.Serializable]
    public class BridgeCall {
        public string name;
        public BridgeArgs args;
    }

    [System.Serializable]
    public class BridgeArgs {
        public string op;
        public string path;
        public int buckets;
        public bool dryRun;
    }

    public static class Bridge {
        public static string Url = "http://127.0.0.1:8787/tools/call";

        public static IEnumerator Call(string tool, BridgeArgs args, System.Action<string> done) {
            var body = JsonUtility.ToJson(new BridgeCall { name = tool, args = args });
            var request = new UnityWebRequest(Url, "POST");
            try {
                request.uploadHandler = new UploadHandlerRaw(Encoding.UTF8.GetBytes(body));
                request.downloadHandler = new DownloadHandlerBuffer();
                request.SetRequestHeader("Content-Type", "application/json");
                yield return request.SendWebRequest();
                // UnityWebRequest.Result arrived in 2020.2; the status code itself works on every version.
                if (request.responseCode >= 200 && request.responseCode < 300) done(request.downloadHandler.text);
                else {
                    Debug.LogWarning("bridge refused: " + request.responseCode + " " + request.error);
                    done(null);
                }
            } finally {
                request.Dispose();
            }
        }
    }

    // The engine's score shape, mirrored. JsonUtility ignores fields it does not know, which is why
    // the engine may add to its answer without breaking this side.
    [System.Serializable] public class ScoreNote {
        public float tick;
        public int note;
        public float ticks;
        public int velocity;
        public int channel;
    }

    [System.Serializable] public class ScoreTrack {
        public string name;
        public int noteCount;
        public ScoreNote[] notes;
    }

    [System.Serializable] public class Score {
        public string path;
        public int format;
        public int ppq;
        public int tempo;
        public string title;
        public int notes;
        public float lastTick;
        public float bars;
        public ScoreTrack[] tracks;
    }

    [System.Serializable] public class PeakBuckets {
        public float[] min;
        public float[] max;
    }

    [System.Serializable] public class PeakAnswer {
        public string path;
        public int sampleRate;
        public int channels;
        public int frames;
        public PeakBuckets buckets;
    }
}
