import requests
import sys

r = requests.get("https://mpc-results.herokuapp.com", params={"computation_id":sys.argv[1]})
print(r.text)