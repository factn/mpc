import subprocess

if __name__ == '__main__':
	import sys
	args = sys.argv[1:]

	while True:
		try:
			nums = subprocess.check_output(["lsof", "-t", "-i", f":{args[0]}"]).decode().split("\n")
			print(nums)
			for num in nums:
				try:
					subprocess.call(["kill", "-9", f"{num}"])
				except:
					pass
		except:
			pass
		try:
			subprocess.call(["python3", "runtriples.py"]+args)
		except Exception as e:
			print(f"STOPPED: {e}")
