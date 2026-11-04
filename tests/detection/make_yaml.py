#!/usr/bin/env python3
"""從 Debian 套件的預設 suricata.yaml 產生偵測評估用的設定：只輸出 eve 的 alert，其餘維持預設。
用法: python3 -I make_yaml.py <default.yaml> <輸出.yaml> [--stats]
  --stats：另外在結束時寫 stats.log（flow 總數等計數器），CICIoT2023 用來算「有 alert 的 flow 比例」的分母。
"""
import sys
import yaml

src, dst = sys.argv[1], sys.argv[2]
c = yaml.safe_load(open(src))
c['outputs'] = [{'eve-log': {
    'enabled': True, 'filetype': 'regular', 'filename': 'eve.json',
    'types': [{'alert': {'metadata': True, 'tagged-packets': False}}],
}}]
c['stats'] = {'enabled': False}
if '--stats' in sys.argv[3:]:
    c['outputs'].append({'stats': {'enabled': True, 'filename': 'stats.log', 'totals': True, 'threads': False}})
    c['stats'] = {'enabled': True, 'interval': 86400}
c['classification-file'] = '/rules/classification.config'
c['reference-config-file'] = '/etc/suricata/reference.config'
c['threshold-file'] = '/etc/suricata/threshold.config'
with open(dst, 'w') as f:
    f.write('%YAML 1.1\n---\n')
    yaml.safe_dump(c, f, sort_keys=False, default_flow_style=False)
