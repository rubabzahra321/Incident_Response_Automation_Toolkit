
import os, hashlib, json, time

def hash_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()

def create_baseline(folder):
    baseline = {}
    for root, dirs, files in os.walk(folder):
        for fn in files:
            path = os.path.join(root, fn)
            try:
                baseline[path] = hash_file(path)
            except Exception as e:
                baseline[path] = str(e)
    # save baseline timestamp
    baseline_meta = {"ts": time.time(), "files": baseline}
    return baseline_meta

def rescan(baseline_meta):
    old = baseline_meta["files"]
    folder_paths = set(old.keys())
    current = {}
    for path in folder_paths:
        if os.path.exists(path):
            try:
                current[path] = hash_file(path)
            except Exception as e:
                current[path] = str(e)
    added = []
    deleted = []
    modified = []
    for path in folder_paths:
        if path not in current:
            deleted.append(path)
        else:
            if current[path] != old[path]:
                modified.append(path)
    # check for new files in same folders
    roots = set(os.path.dirname(p) for p in folder_paths)
    for r in roots:
        for fn in os.listdir(r):
            p = os.path.join(r, fn)
            if p not in old:
                added.append(p)
    return {"added": added, "deleted": deleted, "modified": modified}
