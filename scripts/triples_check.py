import requests, json

r = requests.get("https://safetraceapi.herokuapp.com/api/triples/all", headers={"api_key": "4b6bff10-760e-11ea-bcd4-03a854e8623c"})
j=json.loads(r.text)
print(len(j['triples']))