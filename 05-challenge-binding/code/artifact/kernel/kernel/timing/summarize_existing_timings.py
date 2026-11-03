"""Summarize existing benchmark labels without executing protocol experiments."""
from pathlib import Path
import json
import re
import statistics

ROOT = Path(__file__).resolve().parents[2]
rows = []
for size in (8,100,500):
    path=ROOT/f"_hunt/fresco-bench{size}.log"
    raw=path.read_bytes()
    text=raw.decode("utf-16" if raw.startswith((b'\xff\xfe',b'\xfe\xff')) else "utf-8")
    pairs=[tuple(map(int,m)) for m in re.findall(r"OVERHEAD seed_ns=(\d+) check_ns=(\d+)",text)]
    retained=pairs[2:]
    s=statistics.median(v[0] for v in retained)
    c=statistics.median(v[1] for v in retained)
    rows.append({"batch_size":size,"source":str(path.relative_to(ROOT)),"raw_records":len(pairs),
                 "discarded_records":2,"retained_records":len(retained),"seed_median_ns":s,
                 "check_median_ns":c,"share_of_sum_of_medians":s/(s+c),
                 "ratio_to_check_median_arithmetic_only":s/c,
                 "independent_runs":False,"timer_boundaries_verified":False})
out=Path(__file__).with_name("timing-summary.json")
out.write_text(json.dumps(rows,indent=2),encoding="utf-8")
print(json.dumps(rows,indent=2))
