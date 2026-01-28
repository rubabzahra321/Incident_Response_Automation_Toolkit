
import re
from email import message_from_string
def analyze_header(raw):
    result = {"summary": "", "score": 0, "indicators": [], "details": {}}
    try:
        msg = message_from_string(raw)
    except Exception as e:
        # fallback simple parsing
        msg = None
    # basic checks
    from_field = ""
    try:
        from_field = msg.get("From","") if msg else ""
    except Exception:
        from_field = ""
    result["details"]["From"] = from_field
    # Return-Path
    rp = ""
    try:
        rp = msg.get("Return-Path","") if msg else ""
    except Exception:
        rp = ""
    result["details"]["Return-Path"] = rp
    # Authentication-Results
    ar = ""
    try:
        ar = msg.get("Authentication-Results","") if msg else ""
    except Exception:
        ar = ""
    result["details"]["Auth-Results"] = ar
    # Received lines and IPs
    received = re.findall(r"Received:[^\n]*", raw) or re.findall(r"Received:[^\r\n]*", raw)
    result["details"]["Received"] = received
    # check mismatches
    try:
        from_domain = re.search(r'@([A-Za-z0-9\.-]+)', from_field).group(1) if "@" in from_field else ""
    except Exception:
        from_domain = ""
    rp_domain = ""
    try:
        rp_domain = re.search(r'@([A-Za-z0-9\.-]+)', rp).group(1) if "@" in rp else ""
    except Exception:
        rp_domain = ""
    if from_domain and rp_domain and from_domain != rp_domain:
        result["score"] += 3
        result["summary"] += "From/Return-Path domain mismatch. "
        result["indicators"].append(from_domain)
    # auth results absence/negative
    if not ar:
        result["score"] += 2
        result["summary"] += "Missing Authentication-Results (SPF/DKIM) header. "
    else:
        if "dkim=pass" not in ar.lower():
            result["score"] += 2
            result["summary"] += "DKIM not passing. "
    # suspicious links in body (simple)
    urls = re.findall(r'(https?://[^\s]+)', raw)
    if urls:
        result["details"]["urls"] = urls
        for u in urls:
            if any(x in u for x in ["login","confirm","secure","update"]):
                result["score"] += 1
                result["summary"] += f"Suspicious keyword in URL: {u} "
                result["indicators"].append(u)
    # final severity label
    if result["score"] >= 6:
        label = "High"
    elif result["score"] >= 3:
        label = "Medium"
    else:
        label = "Low"
    result["severity"] = label
    return result
