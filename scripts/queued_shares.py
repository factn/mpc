import requests, json
import sys

if len(sys.argv) >= 2:
	r = requests.get("https://safetraceapi.herokuapp.com/api/shares", json={"node_id": 1, 'computation_id':sys.argv[1]}, headers={"api_key": "4b6bff10-760e-11ea-bcd4-03a854e8623c"})
else:
	r = requests.get("https://safetraceapi.herokuapp.com/api/shares", json={"node_id": 1}, headers={"api_key": "4b6bff10-760e-11ea-bcd4-03a854e8623c"})
j=json.loads(r.text)
print(j)