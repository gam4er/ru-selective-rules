"""Read-only public-source integration verification; writes only evidence/live."""
import json
import os
from pathlib import Path
import sys
import time
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import rules

root=Path(__file__).resolve().parents[1]
upstream=root.parent
out=root/'evidence/live';out.mkdir(parents=True,exist_ok=True)
os.environ['TEMP']=str(out);os.environ['TMP']=str(out)
import tempfile
tempfile.tempdir=str(out)
config=rules.read_json(root/'config.example.json')
config.update(state=str(out/'state'),publisher_state=str(out/'publisher'),sing_box=str(upstream/'vpn-20261027/windows/bin/sing-box-stable.exe'),xray=str(upstream/'vless/diagnostics/20261022/xray/xray.exe'))
start=time.time()
rules.build(config)
before=(Path(config['state'])/'candidate.json').read_bytes()
rules.build(config)
assert before==(Path(config['state'])/'candidate.json').read_bytes(), 'unchanged routing promoted new candidate'
print(json.dumps({'elapsed_seconds':round(time.time()-start,2),'candidate':rules.read_json(Path(config['state'])/'candidate.json')},indent=2))
