#!/usr/bin/env python3
import os, json, requests, re
from datetime import datetime

DATA_DIR = "/opt/clawglancer/public/data"
TOP_PATH = f"{DATA_DIR}/prioritized_threats.json"
DELTA_PATH = f"{DATA_DIR}/delta.json"
META_PATH = f"{DATA_DIR}/meta.json"
LAST_JOKE_PATH = f"{DATA_DIR}/last_joke.txt"
ALERT_JSON_PATH = f"{DATA_DIR}/latest_alert.json"

BOT = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
CHAT = os.getenv("TELEGRAM_CHAT_ID", "").strip()
OPENAI_KEY = os.getenv("OPENAI_API_KEY", "").strip()
OPENAI_MODEL = (os.getenv("OPENAI_MODEL") or "gpt-4.1-mini").strip()

STYLE_FILES = [
    "/opt/clawglancer/app/workspace/ALERT_STYLE.md",
    "/opt/clawglancer/app/workspace/SOUL.md",
    "/opt/clawglancer/app/workspace/IDENTITY.md",
]

FALLBACK_JOKES = [
    "No explosions this hour. Just the usual slow-motion disaster.",
    "The internet is stable in the same way a landfill is stable.",
    "Security is still being treated like a feature request.",
    "Nothing new hit the fan. The fan is still filthy though.",
    "Everything’s fine. This is the same lie software tells itself before a breach.",
]

def tg_send(text: str) -> bool:
    if not BOT or not CHAT:
        print("Telegram: missing TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID (skipping)")
        return False
    url = f"https://api.telegram.org/bot{BOT}/sendMessage"
    payload = {"chat_id": CHAT, "text": text, "disable_web_page_preview": True}
    try:
        r = requests.post(url, json=payload, timeout=10)
        if r.status_code != 200:
            print(f"Telegram: HTTP {r.status_code}: {r.text[:200]}")
            return False
        return True
    except Exception as e:
        print(f"Telegram: exception: {e}")
        return False

def load_json(path, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default

def read_text(path, limit=3000):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()[:limit]
    except Exception:
        return ""

def normalize_line(s: str) -> str:
    return " ".join((s or "").strip().lower().split())

def pick_fallback_no_repeat(previous: str) -> str:
    prev = normalize_line(previous)
    for joke in FALLBACK_JOKES:
        if normalize_line(joke) != prev:
            return joke
    return FALLBACK_JOKES[0]

def clean_summary(s: str, max_len: int = 160) -> str:
    s = (s or "").replace("\n", " ").strip()
    s = " ".join(s.split())
    s = s.replace("http://", "").replace("https://", "")
    if len(s) <= max_len:
        return s
    cut = s[:max_len].rstrip()
    j = max(cut.rfind(". "), cut.rfind("? "), cut.rfind("! "))
    if j >= 80:
        return cut[:j+1].rstrip()
    return cut.rsplit(" ", 1)[0]

def pick_top(items, severity=None):
    for v in items:
        if not severity or (v.get("severity") == severity):
            return v
    return None

def parse_response_text(resp_json) -> str:
    try:
        out = resp_json.get("output") or []
        for item in out:
            if item.get("type") == "message":
                for c in item.get("content", []) or []:
                    if c.get("type") == "output_text" and c.get("text"):
                        return c["text"]
    except Exception:
        pass
    return ""

def gen_llm_one_liner(context: str, previous: str) -> str:
    if not OPENAI_KEY:
        return ""

    style = ""
    for p in STYLE_FILES:
        txt = read_text(p)
        if txt:
            style += f"\n\n---\nFILE: {os.path.basename(p)}\n{txt}"

    instructions = (
        "Write exactly ONE short dry punchline, max 90 characters. "
        "Do NOT repeat or paraphrase any header, CVE ID, severity, score, title, or summary from the context. "
        "Do NOT include these phrases: ClawGlancer update, No big movers, Top #1, CRITICAL, HIGH. "
        "Do NOT mention any CVE number. "
        "Return only the punchline sentence and nothing else."
    )

    prompt = f"PREVIOUS_LINE:\n{previous.strip()}\n\nCONTEXT:\n{context.strip()}\n{style}\n"

    headers = {"Authorization": f"Bearer {OPENAI_KEY}", "Content-Type": "application/json"}
    payload = {
        "model": OPENAI_MODEL,
        "instructions": instructions,
        "input": prompt,
        "temperature": 0.9,
        "max_output_tokens": 60,
    }

    try:
        r = requests.post("https://api.openai.com/v1/responses", headers=headers, json=payload, timeout=20)
        if r.status_code != 200:
            print(f"OpenAI: HTTP {r.status_code}: {r.text[:200]}")
            return ""
        text = parse_response_text(r.json()).strip()
        text = " ".join(text.split())

        banned = [
            "clawglancer update",
            "no big movers",
            "top #1",
            "critical:",
            "high:",
            "cve-",
        ]
        if (not text) or any(b in text.lower() for b in banned):
            return ""
        if previous and normalize_line(text) == normalize_line(previous):
            return ""
        if len(text) > 90:
            text = text[:90].rsplit(" ", 1)[0].rstrip()
        return text
    except Exception as e:
        print(f"OpenAI: exception: {e}")
        return ""


def persist_latest_alert(message: str, generated_at: str) -> None:
    data = {
        "message": message,
        "generated_at": generated_at,
    }
    tmp = ALERT_JSON_PATH + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        os.replace(tmp, ALERT_JSON_PATH)
    except Exception as e:
        print(f"latest_alert.json write failed: {e}")

def main():
    items = load_json(TOP_PATH, [])
    meta = load_json(META_PATH, {})
    delta = load_json(DELTA_PATH, {})
    generated_at = meta.get("generated_at") or datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

    previous = ""
    try:
        previous = open(LAST_JOKE_PATH, "r", encoding="utf-8").read().strip()
    except Exception:
        pass

    if not items:
        one_liner = gen_llm_one_liner("No top list this run.", previous) or pick_fallback_no_repeat(previous)
        msg = "ClawGlancer update ✅\n\nNo top list this run.\nEither the feed is quiet or your filters are savage.\n\n" + one_liner
        persist_latest_alert(msg, generated_at)
        tg_send(msg)
        try:
            open(LAST_JOKE_PATH, "w", encoding="utf-8").write(one_liner)
        except Exception:
            pass
        return

    top1 = items[0]
    top1_id = top1.get("cve_id", "unknown")
    top1_sev = top1.get("severity", "UNK")
    top1_score = top1.get("intel_score") or top1.get("cvss_v3") or "n/a"

    crit = pick_top(items, "CRITICAL")
    high = pick_top(items, "HIGH")

    ctx_lines = [
        f"top_changed={delta.get('top_changed')}",
        f"top1={top1_id} {top1_sev} score={top1_score}",
        f"new_count={delta.get('new_count')} dropped_count={delta.get('dropped_count')}",
    ]
    if crit:
        ctx_lines.append(f"critical={crit.get('cve_id')} summary={clean_summary(crit.get('summary'), 120)}")
    if high:
        ctx_lines.append(f"high={high.get('cve_id')} summary={clean_summary(high.get('summary'), 120)}")

    one_liner = gen_llm_one_liner("\n".join(ctx_lines), previous)
    if not one_liner:
        one_liner = pick_fallback_no_repeat(previous)

    lines = []
    lines.append("ClawGlancer update ✅")
    lines.append("")
    if delta.get("top_changed") is True:
        lines.append(f"Top #1 changed → {top1_id} ({top1_sev}, {top1_score})")
    else:
        lines.append(f"No big movers. Top #1 still {top1_id} ({top1_sev}, {top1_score})")
    lines.append("")

    if crit:
        lines.append("CRITICAL:")
        lines.append(f"  {crit.get('cve_id')} (score {crit.get('intel_score') or crit.get('cvss_v3')})")
        lines.append(f"  {clean_summary(crit.get('summary'))}")
        lines.append("")

    if high:
        lines.append("HIGH:")
        lines.append(f"  {high.get('cve_id')} (score {high.get('intel_score') or high.get('cvss_v3')})")
        lines.append(f"  {clean_summary(high.get('summary'))}")
        lines.append("")

    lines.append(one_liner)

    msg = "\n".join(lines).strip()
    persist_latest_alert(msg, generated_at)
    tg_send(msg)

    try:
        open(LAST_JOKE_PATH, "w", encoding="utf-8").write(one_liner)
    except Exception:
        pass

if __name__ == "__main__":
    main()
