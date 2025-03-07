import time
from zapv2 import ZAPv2

zap = ZAPv2(apikey='eih9sob8710beis5ubeb3th3pd', proxies={'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'})

target = "http://horselaugh.com"

zap.urlopen(target)
scan_id = zap.spider.scan(url=target)

while int(zap.spider.status(scan_id)) < 100:
    time.sleep(2)

alert_results = zap.core.alerts()
for alert in alert_results:
    print('URL: %s, Risk Level: %s' % (alert['url'], alert['risk']))