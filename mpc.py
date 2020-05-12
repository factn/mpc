from serialize import *
from shamir import Shamir
from circuit import Circuit, RuntimeCircuit
from hashlib import sha256
from ecies import encrypt, decrypt, hex2prv
import asyncio, aiohttp, ssl
import json, base64, binascii, random, time, os

class MPCProtocol(asyncio.Protocol):

	def __init__(self, local_peer, client=False):
		self.mpc = local_peer
		self.peer_index = None
		self.current_line = ''
		self.transport = None
		self.client = client

	def connection_made(self, transport):
		self.transport = transport
		peername = self.transport.get_extra_info('peername')
		print(f'Peer {self.mpc.index} received new connection from {peername}')
		if self.client:
			msg = json.dumps({'msgtype': 'bootstrap', 'index': self.mpc.index, 'port':self.mpc.port, 'ptype': self.mpc.protocol_type}) + '\n'
			self.transport.write(msg.encode())

	def data_received(self, data):
		self.current_line += data.decode()
		if len(self.current_line) == 0 or self.current_line[-1] != '\n':
			return
		else:
			try:
				msg = json.loads(self.current_line)
				if msg['msgtype'] == 'bootstrap':
					self.handle_bootstrap_msg(msg)
				elif msg['msgtype'] == 'mpc':
					self.handle_mpc_msg(msg)
				elif msg['msgtype'] == 'triple-id':
					self.handle_triple_id_msg(msg)
			except:
				pass
			self.current_line = ''

	def connection_lost(self, exception):
		if self.peer_index != None:
			del self.mpc.peers[self.peer_index]
			print(f"Peer {self.mpc.index} disconnected from peer {self.peer_index} -- ({len(self.mpc.peers)} total peers)")

	def handle_mpc_msg(self, msg):
		if msg['pid'] not in self.mpc.active_ops:
			if self.mpc.protocol_type == "TRIPLE":
				self.mpc.active_ops[msg['pid']] = {i+1: {} for i in range(2)}
			if self.mpc.protocol_type == "MPC":
				self.mpc.active_ops[msg['pid']] = {i+1: {} for i in range(len(self.mpc.default_circuit.circuit_layers))}
		op_round = self.mpc.active_ops[msg['pid']][msg['round']]
		if self.peer_index not in op_round.keys():
			if msg['datatype'] == "TRIP-AB":
				data = deserialize_triple_ab_msg(msg['data'])
			elif msg['datatype'] == "TRIP-C":
				data = deserialize_triple_c_msg(msg['data'])
			elif msg['datatype'] == "MUL":
				data = deserialize_mul_msg(msg['data'])
			else:
				raise ValueError(f"Unrecognized mpc msgtype: {msg['msgtype']}")
			op_round[self.peer_index] = data

	def send_mpc_msg(self, data, data_type, pid, round_n):
		msg = json.dumps({'msgtype': 'mpc', 'data': data, 'datatype':data_type, 'pid': pid, 'round': round_n}) + '\n'
		self.transport.write(msg.encode())

	def handle_bootstrap_msg(self, msg):
		peername = self.transport.get_extra_info('peername')
		try:
			found = False
			for host, port, index in self.mpc.bootstrap:
				if (host == peername[0]) and (msg['port'] == port) and (msg['index'] == index) and (msg['ptype'] == self.mpc.protocol_type):
					self.mpc.peers[index] = self
					print(f"Peer {self.mpc.index} added peer {self.peer_index} -- ({len(self.mpc.peers)} total peers)")
					found = True
					self.peer_index = index
			if not found:
				raise ValueError("not in bootstrap list")
		except Exception as e:
			print(f"Disconnecting from {peername}: {e}")
			self.transport.close()
		if not self.client:
			resp = json.dumps({'msgtype': 'bootstrap', 'index': self.mpc.index, 'port':self.mpc.port, 'ptype': self.mpc.protocol_type}) + '\n'
			self.transport.write(resp.encode())
		if len(self.mpc.peers) == self.mpc.n-1:
			if self.mpc.protocol_type == 'TRIPLE':
				try:
					self.mpc.triple_task.cancel()
				except:
					pass
				self.mpc.triple_task = self.mpc.loop.create_task(self.mpc.triples_loop())
			if self.mpc.protocol_type == 'MPC':
				try:
					self.mpc.main_task.cancel()
				except:
					pass
				self.mpc.main_task = self.mpc.loop.create_task(self.mpc.main_loop())

	def handle_triple_id_msg(self, msg):
		if self.peer_index not in self.mpc.triple_id.keys():
			self.mpc.triple_id[self.peer_index] = msg['id']

	def send_triple_id_msg(self, id_):
		msg = json.dumps({'msgtype': 'triple-id', 'id': id_}) + '\n'
		self.transport.write(msg.encode())

class MPCPeer:

	def __init__(self, port, t, n, index, priv_hex, bootstrap, protocol_type, circuit_dir=None, certfile=None, keyfile=None, cafile=None, api_endpoint=None, api_key=None):
		self.port = port
		self.t = t
		self.n = n
		self.index = index
		self.private_key = priv_hex
		self.bootstrap = bootstrap
		self.protocol_type = protocol_type
		self.circuit_dir = circuit_dir
		if self.circuit_dir == None:
			self.circuit_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'bristol_circuits')
		self.certfile = certfile
		if self.certfile == None:
			self.certfile = os.path.join(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'certs'), f'node-{self.index}-test.crt')
		self.keyfile = keyfile
		if self.keyfile == None:
			self.keyfile = os.path.join(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'certs'), f'node-{self.index}-test.key')
		self.cafile = cafile
		if self.cafile == None:
			self.cafile = os.path.join(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'certs'), 'testCA.pem')
		self.api_endpoint = api_endpoint
		self.api_key = api_key
		self.loop = asyncio.get_event_loop()
		self.default_circuit = Circuit(os.path.join(self.circuit_dir, "unnormalized_subregion_2_1.txt"), ['V' for _ in range(64)]+['S' for _ in range(6)])
		self.shamir = Shamir(self.t, self.n)
		self.public_key = binascii.hexlify(hex2prv(self.private_key).public_key.format(True)).decode()
		self.peers = {}
		self.active_ops = {}
		self.triples = []
		self.triple_id = {}
		self.triple_round = 0
		self.triple_task = None
		self.main_task = None

	def start(self):
		self.loop.run_until_complete(self.bootstrap_and_start())
		self.loop.run_forever()

	async def bootstrap_and_start(self):
		ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
		ssl_ctx.options |= ssl.OP_NO_TLSv1
		ssl_ctx.options |= ssl.OP_NO_TLSv1_1
		ssl_ctx.options |= ssl.OP_SINGLE_DH_USE
		ssl_ctx.options |= ssl.OP_SINGLE_ECDH_USE
		ssl_ctx.load_cert_chain(self.certfile, self.keyfile)
		ssl_ctx.load_verify_locations(cafile=self.cafile)
		ssl_ctx.check_hostname = False
		ssl_ctx.verify_mode = ssl.VerifyMode.CERT_REQUIRED
		ssl_ctx.set_ciphers('ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384')
		server = await self.loop.create_server(lambda: MPCProtocol(self), '0.0.0.0', self.port, ssl=ssl_ctx, start_serving=False)
		print(f'Peer {self.index} starting at 0.0.0.0:{self.port}')
		for host, port, index in self.bootstrap:
			try:
				await self.connect_to_mpc_peer(host, port, index)
			except Exception as e:
				print(f"Failed to connect: {e}")
		async with server:
			await server.serve_forever()

	async def main_loop(self):
		print('starting main loop...')
		wait = False
		n_users = 2
		while len(self.peers) == self.n-1:
			if int(time.time())%60 < 10 and not wait:
				r_shr = await get_request(os.path.join(self.api_endpoint, "shares"), {"node_id": self.index}, self.api_key)
				jr = json.loads(r_shr)
				id_ = jr["computation_id"]
				shrs = jr['shares']
				if len(shrs) == n_users:
					print("get triples...")
					r = await get_request(os.path.join(self.api_endpoint, "triples/all"), None, self.api_key)
					msg = json.loads(r)
					all_triples = msg["triples"]
					node_triples = [[] for _ in range(self.n)]
					get_triple = None
					for nidx in range(1, self.n+1):
						for triple in all_triples:
							if triple["node_id"] == nidx:
								node_triples[nidx-1].append(triple["triple_id"])
					for i in range(len(node_triples)):
						node_triples[i] = list(sorted(node_triples[i]))
					for triple in node_triples[0]:
						if all([triple in n for n in node_triples]):
							get_triple = triple
							break
					print(f'next triple: {get_triple}')
					r_trip = await get_request(os.path.join(self.api_endpoint, "triples"), {'triple_id': get_triple, 'node_id':self.index}, self.api_key)
					encrypted_shares = base64.b64decode(json.loads(r_trip)['share'])
					triples_json = decrypt(self.private_key, encrypted_shares)
					triples = deserialize_triples(json.loads(triples_json.decode())['data'])
					print("triples len:", len(triples))
					print("id: ", id_)
					zeros = [0 for _ in range(64)]
					all_inputs = []
					for s in shrs:
						try:
							enc_share = base64.b64decode(s["share"])
							share_json = decrypt(self.private_key, enc_share)
							#print(share_json.decode())
							bshares = json.loads(share_json.decode())
							shares = deserialize_shares(bshares["data"])
							#print("share len:", len(shares))
							all_inputs.append(shares)
						except Exception as e:
							print(f"error getting shares: {e}")
							break
					if len(all_inputs) == n_users:
						n_regions = len(all_inputs[0])-2
						print("number of regions: ", n_regions)
						shares = []
						n_triples = 70*n_users
						for n_region in range(n_regions):
							trips = [triples.pop() for _ in range(n_triples)]
							ins = []
							for inp in all_inputs:
								ins.extend( [inp[0], inp[1], inp[n_region+2]])
							inputs = zeros + ins
							print(f"running circuit for region # {n_region+1}...")
							try:
								res_shares = await asyncio.wait_for(self.run_circuit(id_+f'_{n_region+1}', self.default_circuit, inputs, trips), timeout=300)
							except Exception as e:
								print(f"Failed to run circuit: {e}")
								wait = True
								break
							bshr = serialize_shares(res_shares)
							b = json.dumps(bshr)
							shares.append({'area_id':n_region+1, 'share':b})
						if len(shares) == n_regions:
							msg = {'shares': shares, 'computation_id':id_, 'node_id':self.index}
							r = await post_request(os.path.join(self.api_endpoint, "results"), msg, self.api_key)
							print(f"resp: {r}")
							wait = True
			elif int(time.time())%60 < 10 and wait:
				pass
			else:
				wait = False
		print("ending main loop...")
		for task in asyncio.Task.all_tasks():
			task.cancel()
		self.loop.stop()

	async def triples_loop(self):
		global_start = time.time()
		print('starting triples loop')
		self.triples = []
		self.triple_round = 0
		self.active_ops[f'TRIPLES-{self.triple_round}'] = {i+1: {} for i in range(2)}
		while len(self.peers) == self.n-1:
			try:
				start = time.time()
				print(f"begin triples operation {self.triple_round}...")
				triples = await asyncio.wait_for(self.generate_triples(f'TRIPLES-{self.triple_round}', 10000), timeout=120)
				self.triples.extend(triples)
				print(f"finished round {self.triple_round}")
				print(f"triples: {len(self.triples)}, time: {round(time.time()-start, 4)}")
				del self.active_ops[f'TRIPLES-{self.triple_round}']
				if len(self.triples) < 100000:
					self.triple_round += 1
					if f'TRIPLES-{self.triple_round}' not in self.active_ops:
						self.active_ops[f'TRIPLES-{self.triple_round}'] = {i+1: {} for i in range(2)}
				else:
					self.triple_round = 0
					if f'TRIPLES-{self.triple_round}' not in self.active_ops:
						self.active_ops[f'TRIPLES-{self.triple_round}'] = {i+1: {} for i in range(2)}
					my_id = ''.join([random.choice('abcdef0123456789') for _ in range(10)])
					self.triple_id[self.index] = my_id
					for i in range(1, self.n+1):
						if i != self.index:
							self.peers[i].send_triple_id_msg(my_id)
					id_ = await self.gather_triple_id()
					self.triple_id = {}
					print(f"triples id: {id_[:10]} time: {round(time.time()-global_start, 4)}")
					data = serialize_triples(self.triples)
					self.triples = []
					shrs = json.dumps({'data': data})
					encrypted_shares = encrypt(self.public_key, shrs.encode())
					msg = {'share': base64.b64encode(encrypted_shares).decode(), 'triple_id': id_[:10], 'node_id': self.index, 'api_key': self.api_key}
					print("share length:", len(msg['share']))
					if self.api_endpoint != None:
						r = await post_request(os.path.join(self.api_endpoint, "triples"), msg, self.api_key)
						print("triples posted:", r)
					else:
						print("no api address set - not posting")
					global_start = time.time()
			except Exception as e:
				print(f"Triples loop failed: {e}")
				break
		print('ending triples loop')
		for task in asyncio.Task.all_tasks():
			task.cancel()
		self.loop.stop()

	async def connect_to_mpc_peer(self, host, port, index):
		try:
			ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
			ssl_ctx.options |= ssl.OP_NO_TLSv1
			ssl_ctx.options |= ssl.OP_NO_TLSv1_1
			ssl_ctx.load_cert_chain(self.certfile, keyfile=self.keyfile)
			ssl_ctx.load_verify_locations(cafile=self.cafile)
			ssl_ctx.check_hostname = False
			ssl_ctx.verify_mode = ssl.VerifyMode.CERT_REQUIRED
			ssl_ctx.set_ciphers('ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384')
			await asyncio.wait_for(self.loop.create_connection(lambda: MPCProtocol(self, client=True), host, port, ssl=ssl_ctx), timeout=5)
		except Exception as e:
			print(f"Failed to connect to {host}:{port} -- {e}")

	async def generate_triples(self, id_, batch_size):
		msgs = self.shamir.generate_triples_round_1(batch_size)
		for i in range(1, self.n+1):
			if i != self.index:
				self.peers[i].send_mpc_msg(serialize_triple_ab_msg(msgs[i-1]), "TRIP-AB", id_, 1)
		resps = await self.gather_mpc_msgs(id_, 1, self.n-1)
		resps.append(msgs[self.index-1])
		a_shares, b_shares, msgs = self.shamir.generate_triples_round_2(resps)
		for i in range(1, self.n+1):
			if i != self.index:
				self.peers[i].send_mpc_msg(serialize_triple_c_msg(msgs[i-1]), "TRIP-C", id_, 2)
		resps = await self.gather_mpc_msgs(id_, 2, self.n-1)		
		resps.append(msgs[self.index-1])
		return self.shamir.generate_triples_round_3(a_shares, b_shares, resps)

	async def run_circuit(self, id_, circuit, inputs, triples):
		if id_ not in self.active_ops.keys():
			self.active_ops[id_] = {i+1: {} for i in range(len(circuit.circuit_layers))}
		runtime = RuntimeCircuit(circuit, inputs, triples=triples, shamir=self.shamir)
		for i in range(len(runtime.circuit_layers)):
			print(f"starting layer {i+1}...")
			idxs, x, y, send_shares, cs = runtime.compute_layer(i)
			if len(idxs) > 0:
				msg = serialize_mul_msg(send_shares)
				for j in range(1, self.n+1):
					if j != self.index:
						self.peers[j].send_mpc_msg(msg, "MUL", id_, i+1)
				print("gathering layer ", i+1)
				resps = await self.gather_mpc_msgs(id_, i+1, self.t)
				resps.append(send_shares)
				runtime.finish_layer(idxs, x, y, resps, cs)
		return runtime.get_outputs()

	async def gather_mpc_msgs(self, pid, round_n, target_n):
		while len(self.active_ops[pid][round_n]) < target_n:
			await asyncio.sleep(0.25)
		return [i for i in self.active_ops[pid][round_n].values()]

	async def gather_triple_id(self):
		while len(self.triple_id) < self.n:
			await asyncio.sleep(0.25)
		raw_string = ''
		for i in range(1, self.n+1):
			for k, v in self.triple_id.items():
				if k == i:
					raw_string += v
					break
		return sha256(raw_string.encode()).hexdigest()


async def post_request(url, data, api_key):
	async with aiohttp.ClientSession() as session:
		async with session.post(url, json=data, headers={'api_key': api_key}) as resp:
			return await resp.text()

async def get_request(url, data, api_key):
	async with aiohttp.ClientSession() as session:
		async with session.get(url, json=data, headers={'api_key': api_key, 'content-type':'application/json'}) as resp:
			return await resp.text()
