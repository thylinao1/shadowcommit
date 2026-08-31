import json, os, sys, time, urllib.request

BASE = os.environ["ARK_BASE_URL"]; KEY = os.environ["ARK_API_KEY"]
MODELS = sys.argv[1:]

def call(model, prompt, max_out=512):
    body = json.dumps({"model": model, "input": prompt, "max_output_tokens": max_out}).encode()
    req = urllib.request.Request(f"{BASE}/responses", data=body,
        headers={"Authorization": f"Bearer {KEY}", "Content-Type": "application/json"})
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            d = json.loads(r.read())
    except Exception as e:
        return {"model": model, "err": f"{type(e).__name__}: {e}", "secs": round(time.time()-t0,1)}
    txt = ""
    for o in d.get("output", []):
        for c in (o.get("content") or []):
            txt += c.get("text", "")
    u = d.get("usage") or {}
    return {"model": model, "status": d.get("status"), "text": txt.strip()[:120],
            "in": u.get("input_tokens"), "out": u.get("output_tokens"),
            "secs": round(time.time()-t0,1)}

P = "You are a coding agent. Reply with exactly the word READY and nothing else."
for m in MODELS:
    print(json.dumps(call(m, P)))
