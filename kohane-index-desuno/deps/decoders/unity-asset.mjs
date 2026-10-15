// Unity asset files, read natively.
//
// A Unity project keeps its scenes, prefabs and assets as YAML: a stream of documents, each headed by
// `--- !u!<classId> &<fileId>`, that reference each other by GUID. KID's own reader, registered in
// deps/manifest.json; the format is documented by Unity, so nothing here was recovered from a binary.
//
// What it answers is what an index wants: how many objects a file holds, of which classes, what names
// they carry, and which GUIDs it depends on - without launching the editor.
import fs from "node:fs";
import { pathToFileURL } from "node:url";

/** Unity's class ids, the handful an index actually reports by name. */
const CLASS_IDS = {
  1: "GameObject", 4: "Transform", 20: "Camera", 21: "Material", 23: "MeshRenderer",
  33: "MeshFilter", 43: "Mesh", 48: "Shader", 54: "Rigidbody", 65: "BoxCollider",
  74: "AnimationClip", 82: "AudioSource", 95: "Animator", 104: "RenderSettings",
  108: "Light", 111: "Animation", 114: "MonoBehaviour", 115: "MonoScript",
  128: "Font", 137: "SkinnedMeshRenderer", 143: "CharacterController", 157: "LightmapSettings",
  196: "NavMeshSettings", 212: "SpriteRenderer", 213: "Sprite", 222: "CanvasRenderer",
  223: "Canvas", 224: "RectTransform", 225: "CanvasGroup", 1001: "PrefabInstance",
  1002: "PrefabAsset", 1003: "PrefabAsset", 1004: "PrefabInstance",
};

export const capabilities = {
  id: "unity-asset",
  kohaneName: "Kohane Bassline Scene/Asset Reader (Unity)",
  container: "unity asset yaml (scene / prefab / asset / meta)",
  read: { level: "metadata", detail: "document stream walk, class ids and file ids, object names, GUID dependencies, and .meta guid plus importer" },
  decode: { level: "none", detail: "not applicable: the file is text and is read whole" },
  encode: { level: "none", detail: "no writer" },
  verifiedAgainst: "a synthesised scene and .meta whose values were chosen in advance",
};

const docHead = /^--- !u!(\d+) &(\d+)/;

export function readUnityAsset(file, options = {}) {
  const buf = fs.readFileSync(file);
  // Unity writes a UTF-8 BOM on Windows; JSON.parse would reject it and so would a strict regex.
  const text = buf.toString("utf8").replace(/^\uFEFF/, "");
  const lines = text.split(/\r?\n/);
  const limit = options.limit || 200000;

  const out = {
    kind: "unity-asset",
    documents: 0,
    classes: {},
    classNames: {},
    guids: [],
    names: [],
    scriptGuids: [],
    hasPrefabInstance: false,
    metaGuid: null,
    importer: null,
  };

  const guidSet = new Set();
  let current = null;

  for (let i = 0; i < lines.length && i < limit; i++) {
    const head = docHead.exec(lines[i]);
    if (head) {
      out.documents++;
      current = { classId: Number(head[1]), fileId: head[2] };
      const key = String(current.classId);
      out.classes[key] = (out.classes[key] || 0) + 1;
      out.classNames[key] = CLASS_IDS[current.classId] || `Class${key}`;
      if (current.classId === 1001 || current.classId === 1004) out.hasPrefabInstance = true;
      continue;
    }
    // a .meta file is a different shape: one document with a guid and an importer
    if (/^guid:\s*[0-9a-f]{32}$/.test(lines[i].trim())) {
      out.metaGuid = lines[i].split(":")[1].trim();
    }
    if (/^  \w+:\s*$/.test(lines[i]) && /Importer:/.test(lines[i])) {
      out.importer = lines[i].trim().replace(/:$/, "");
    }
    if (/^\w+Importer:/.test(lines[i].trim())) {
      out.importer = lines[i].trim().replace(/:$/, "");
    }
    const name = /^\s+m_Name:\s*(.+)$/.exec(lines[i]);
    if (name && out.names.length < 40) {
      const value = name[1].trim().replace(/^["']|["']$/g, "");
      if (value) out.names.push(value);
    }
    // references are written as {fileID: N, guid: <32 hex>, type: 3}
    for (const g of lines[i].matchAll(/guid:\s*([0-9a-f]{32})/g)) guidSet.add(g[1]);
    if (current && /m_Script:/.test(lines[i])) {
      const g = /guid:\s*([0-9a-f]{32})/.exec(lines[i]);
      if (g && !out.scriptGuids.includes(g[1])) out.scriptGuids.push(g[1]);
    }
  }

  out.guids = [...guidSet];
  if (out.metaGuid) {
    out.guids = [...new Set([out.metaGuid, ...out.guids])];
  }
  out.guidCount = out.guids.length;
  out.pending = "components are counted, not interpreted: no serialised object is reconstructed";
  return out;
}

const isMain = process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url;
if (isMain) {
  const file = process.argv[2];
  if (!file) { console.log("usage: node unity-asset.mjs <file.unity|file.prefab|file.asset|file.meta>"); process.exit(1); }
  const r = readUnityAsset(file);
  console.log(file);
  console.log(`  ${r.documents} document(s), ${r.guidCount} guid(s)${r.metaGuid ? ` (meta guid ${r.metaGuid.slice(0, 8)}...)` : ""}`);
  for (const [id, n] of Object.entries(r.classes)) console.log(`  class ${id} ${r.classNames[id]}: ${n}`);
  if (r.names.length) console.log(`  names: ${r.names.slice(0, 8).join(", ")}`);
  if (r.importer) console.log(`  importer: ${r.importer}`);
}
