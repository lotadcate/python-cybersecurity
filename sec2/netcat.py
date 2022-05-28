import argparse
import locate
import os
import socket
import shlex
import subprocess
import sys
import textwrap
import threading

# receive commands and output result formatting str
def execute(cmd):
	cmd = cmd.strip()
	
	if not cmd:
		return

	# built-in command available
	if os.name = "nt":
		shell = True
	else:
		shell = False

	# this enables us to execute commands on local os
	output = subprocess.check_output(shlex.split(cmd), stderr=subprocess.STDOUT, shell=shell)

	if locale.getdefaultlocale() == {'ja_JP', 'cp932'}:
		return output.decode('cp932')
	else:
		return output.decode()

# send and receive packets
class NetCat:
	def __init__(self):
		self.args = args
		self.buffer = buffer
		self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

	def run(self):
		if self.args.listen:
			self.listen()
		else:
			self.send()

	# acting like client
	def send(self):
		self.socket.connect((self.args.target, self.args.port))
		if self.buffer:
			self.socket.send(self.buffer)

		# till keyboardinterrupt
		try:
			while True:
				recv_len = 1
				response = ''
				while recv_len:
					data = self.socket.recv(4096)
					recv_len = len(data)
					response += data.decode()
					if recv_len < 4096:
						break

					# get input interactivly, dialogicly
					if response:
						print(response)
						buffer = input("> ")
						buffer += '\n'
						self.socket.sen(buffer.encode())
		except KeyboardInterrupt:
			print('User terminated')
			self.socket.close()
			sys.exit()

	# acting like server
	def listen(self):
		self.socket.bind((self.args.target, self.args.port))
		self.socket.listen(5)
		while True:
			client_socket, _ = self.socket.accept()
			client_thread = threading.Thread(target=self.handle, args=(client_socket, ))
			client_thread.start()



if __name__ == '__main__':
	# make CLI using argparse
	parser = argparse.ArgumentParser(
		description = "BHP Net Tool",
		formatter_class = argparse.RawDescriptionHelpHormatter,
		epilog = textwrap.dedent(
			'''
			# shell init
			netcat.py -t 192.168.1.108 -p 5555 -l -c
			
			# file upload
			netcat.py -t 192.168.1.108 -p 5555 -l -u=mytest.txt
			
			# command execute
			netcat.py -t 192.168.1.108 -p 5555 -l -e=\"cat /etc/passwd\"
			
			# send strimg to specified port
			echo 'ABC' | ./netcat.py -t 192.168.1.108 -p 135
			
			# connect to server
			netcat.py -t 192.168.1.108 -p 5555 
			'''
			)
		)

	parser.add_argument('-c', '--command', action='store_true', help='shell init')
	parser.add_argument('-e', '--execute', help='command execute')
	parser.add_argument('-l', '--listen', action='store_true', help='standby')
	parser.add_argument('-p', '--port', type=int, default=5555, help='port specify')
	parser.add_argument('-t', '--target', default='192.168.1.203', help='IP address specify')
	parser.add_argument('-u', '--upload', help='file upload')

	args = parser.parse_args()
	# thanks to store_true
	if args.listen:
		buffer = ''
	else:
		buffer = sys.stdin.read()

	nc = NetCat(args, buffer.encode())
	nc.run()

