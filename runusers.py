import requests, json, base64
from ecies import encrypt
from shamir import Shamir
from serialize import serialize_shares
import time, random

if __name__ == '__main__':
	while True:
		for i in range(2):
			vals = ['1', '1'] + [random.choice(['0', '1']) for _ in range(25)]
			shares = Shamir(1, 3).share_bitstring_secret(vals)
			pubkeys = ['03e49a88bf6889414e27890ed1f29c615cdfe22aff448b7396ced9c05a29a150d0', '0389c6a273d34941bddd01af256f5a460870fe74064e45dc2ad74c9a15df040090', '02c1cdca9a7491b807fe64a2bcf719086e46f0ecc9ff510a3771b94d9a788e2bd7']
			enc_shares = []
			for i in range(3):
				shr = json.dumps(serialize_shares(shares[i]))
				share = encrypt(pubkeys[i], shr.encode())
				enc_shares.append(base64.b64encode(share))
			msg = {'shares': [{'node_id':i+1, 'share': enc_shares[i].decode()} for i in range(3)]}
			r = requests.post("https://safetraceapi.herokuapp.com/api/shares", json=msg, headers={"api_key": "4b6bff10-760e-11ea-bcd4-03a854e8623c"})
			j=json.loads(r.text)
			print(j)
		print("waiting...")
		time.sleep(600)