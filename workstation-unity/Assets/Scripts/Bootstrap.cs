// Bootstrap: the whole scene is created here, so the project needs no hand-written scene file.
//
// An empty Unity scene is enough. This runs before the first scene loads, creates the camera and the
// light, hangs the waterfall on an object and hands it a score path - from KOHANE_SCORE if the
// environment sets one, otherwise from a small file under StreamingAssets, otherwise from the field
// below. That keeps "which piece am I looking at" a runtime choice rather than a rebuild.
using System.IO;
using UnityEngine;

namespace Kohane {

    public class Bootstrap : MonoBehaviour {
        [Tooltip("Used when neither KOHANE_SCORE nor StreamingAssets/kohane-score-path.txt says otherwise")]
        public string defaultScorePath = "";

        [RuntimeInitializeOnLoadMethod(RuntimeInitializeLoadType.BeforeSceneLoad)]
        private static void Create() {
            var go = new GameObject("kohane-waterfall");
            DontDestroyOnLoad(go);

            var camera = Camera.main;
            if (camera == null) {
                var cameraGo = new GameObject("main-camera");
                camera = cameraGo.AddComponent<Camera>();
                cameraGo.tag = "MainCamera";
                camera.orthographic = true;
                camera.orthographicSize = 5.5f;
                camera.clearFlags = CameraClearFlags.SolidColor;
                camera.backgroundColor = new Color(0.09f, 0.08f, 0.07f);   // the theme's ink-dark surface
                camera.transform.position = new Vector3(0f, 0f, -10f);
                DontDestroyOnLoad(cameraGo);
            }

            var light = new GameObject("key-light");
            var lamp = light.AddComponent<Light>();
            lamp.type = LightType.Directional;
            lamp.intensity = 1f;
            light.transform.rotation = Quaternion.Euler(50f, -30f, 0f);
            DontDestroyOnLoad(light);

            var waterfall = go.AddComponent<Waterfall>();
            waterfall.scorePath = ResolveScorePath();
            if (string.IsNullOrEmpty(waterfall.scorePath)) {
                Debug.Log("no score path: set KOHANE_SCORE, or write one into StreamingAssets/kohane-score-path.txt");
            }
        }

        private static string ResolveScorePath() {
            var fromEnv = System.Environment.GetEnvironmentVariable("KOHANE_SCORE");
            if (!string.IsNullOrEmpty(fromEnv)) return fromEnv;
            var sidecar = Path.Combine(Application.streamingAssetsPath, "kohane-score-path.txt");
            if (File.Exists(sidecar)) {
                var line = File.ReadAllText(sidecar).Trim();
                if (!string.IsNullOrEmpty(line)) return line;
            }
            return "";
        }
    }
}
