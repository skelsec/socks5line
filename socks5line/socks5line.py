import asyncio
import ipaddress
import traceback

from socks5line import logger
from socks5line.protocol.socks5 import SOCKS5Method, SOCKS5Nego, SOCKS5NegoReply, SOCKS5Command, SOCKS5Request, SOCKS5ReplyType, SOCKS5Reply, SOCKS5PlainAuth



class Socks5LineProxyServer:
	def __init__(self):
		self.ip = None
		self.port = 1080
		self.timeout = 1
		self.username = None
		self.password = None

	@staticmethod
	def from_connection_string(x):
		"""
		user:pass@ip:port
		or
		ip:port
		or
		ip
		"""
		ps = Socks5LineProxyServer()

		t = x
		if x.find('@') != -1:
			u, t = x.rsplit('@', 1)
			ps.username, ps.password = u.split(':')
			
			
		if t.find(':') == -1:
			ps.ip = t
			return ps
		ps.ip, ps.port = t.split(':')
		ps.port = int(ps.port)
		return ps

def breakout_from_thread(loop):
	asyncio.set_event_loop(loop)
	loop.run_forever()

class SOCKS5Line:
	def __init__(self, proxy, target_ip, target_port, listen_ip = '127.0.0.1', listen_port = 11111):
		self.target_ip = target_ip
		self.target_port = target_port

		self.proxy = proxy

		self.listen_ip = listen_ip
		self.listen_port = listen_port

		self.proxy_tasks = []
		self.sock = None

	async def socks5_connect(self):
		con = asyncio.open_connection(self.proxy.ip, self.proxy.port)
		try:
			proxy_reader, proxy_writer = await asyncio.wait_for(con, self.proxy.timeout)
		except asyncio.TimeoutError:
			logger.debug('[SOCKS5Line] Proxy Connection timeout')
			raise
			
		except ConnectionRefusedError:
			logger.debug('[SOCKS5Line] Proxy Connection refused')
			raise
			
		except asyncio.CancelledError:
			#the SMB connection is terminating
			raise asyncio.CancelledError
			
		except Exception as e:
			logger.debug('[SOCKS5Line] connect generic exception')
			raise e

		
		#logger.info('Establishing proxy connection %s => %s' % (server.get_paddr(), target.get_paddr()))
		authmethods = [SOCKS5Method.NOAUTH]
		if self.proxy.username is not None:
			authmethods.append(SOCKS5Method.PLAIN)
		
		#logger.debug('Sending negotiation command to %s:%d' % proxy_writer.get_extra_info('peername'))
		proxy_writer.write(SOCKS5Nego.construct(authmethods).to_bytes())
		await asyncio.wait_for(proxy_writer.drain(), timeout = self.proxy.timeout)

		rep_nego = await asyncio.wait_for(SOCKS5NegoReply.from_streamreader(proxy_reader), timeout = self.proxy.timeout)
		logger.debug('Got negotiation reply from %s: %s' % (proxy_writer.get_extra_info('peername'), repr(rep_nego)))
		
		if rep_nego.METHOD == SOCKS5Method.PLAIN:
			logger.debug('Preforming plaintext auth to %s:%d' % proxy_writer.get_extra_info('peername'))
			proxy_writer.write(SOCKS5PlainAuth.construct(self.proxy.username, self.proxy.password).to_bytes())
			await asyncio.wait_for(proxy_writer.drain(), timeout=self.proxy.timeout)
			rep_auth_nego = await asyncio.wait_for(SOCKS5NegoReply.from_streamreader(proxy_reader), timeout = self.proxy.timeout)

			if rep_auth_nego.METHOD != SOCKS5Method.NOAUTH:
				raise Exception('Failed to connect to proxy %s:%d! Authentication failed!' % proxy_writer.get_extra_info('peername'))

		logger.debug('Sending connect request to %s:%d' % proxy_writer.get_extra_info('peername'))
		proxy_writer.write(SOCKS5Request.construct(SOCKS5Command.CONNECT, self.target_ip, self.target_port).to_bytes())
		await asyncio.wait_for(proxy_writer.drain(), timeout=1)

		rep = await asyncio.wait_for(SOCKS5Reply.from_streamreader(proxy_reader), timeout=self.proxy.timeout)
		if rep.REP != SOCKS5ReplyType.SUCCEEDED:
			logger.info('Failed to connect to proxy %s! Server replied: %s' % (proxy_writer.get_extra_info('peername'), repr(rep.REP)))
			raise Exception('Authentication failure!')
		
		logger.debug('Server reply from %s : %s' % (proxy_writer.get_extra_info('peername'),repr(rep)))

		if rep.BIND_ADDR == ipaddress.IPv6Address('::') or rep.BIND_ADDR == ipaddress.IPv4Address('0.0.0.0') or rep.BIND_PORT == proxy_writer.get_extra_info('sockname')[1]:
			logger.debug('Same socket can be used now on %s:%d' % (proxy_writer.get_extra_info('peername')))
			#this means that the communication can continue on the same socket!
			logger.info('Proxy connection succeeded')
			return proxy_reader, proxy_writer

		else:
			#this case, the server created the socket, but expects a second connection to a different ip/port
			con = asyncio.open_connection(str(rep.BIND_ADDR), rep.BIND_PORT)
			try:
				reader, writer = await asyncio.wait_for(con, self.proxy.timeout)
			except asyncio.TimeoutError:
				logger.debug('[SOCKS5Line] Proxy Connection timeout')
				raise
				
			except ConnectionRefusedError:
				logger.debug('[SOCKS5Line] Proxy Connection refused')
				raise
				
			except asyncio.CancelledError:
				#the SMB connection is terminating
				raise asyncio.CancelledError
				
			except Exception as e:
				logger.debug('[SOCKS5Line] connect generic exception')
				raise e
			
			else:
				writer.close()
				return reader, writer
		
	async def handle_proxy(self, reader, writer, stop_evt):
		try:
			while True:
				await asyncio.sleep(0)
				data = await reader.read(2048)
				if data is None or data == b'':
					raise Exception('Remote socket terminated!')

				writer.write(data)
				await writer.drain()
		except Exception as e:
			writer.close()
			stop_evt.set()

	async def watchdog(self, channel_1, channel_2, stop_evt):
		await stop_evt.wait()
		channel_1.cancel()
		channel_2.cancel()

	async def handle_echo(self, reader, writer):
		try:
			proxy_reader, proxy_writer = await asyncio.wait_for(self.socks5_connect(), timeout = self.proxy.timeout + 1 if self.proxy.timeout else None)
			
			stop_evt = asyncio.Event()
			channel_1 = asyncio.create_task(self.handle_proxy(reader, proxy_writer, stop_evt))
			channel_2 = asyncio.create_task(self.handle_proxy(proxy_reader, writer, stop_evt))
			doggy = asyncio.create_task(self.watchdog(channel_1, channel_2, stop_evt))

			self.proxy_tasks.append( (channel_1, channel_2, doggy) )
		except:
			traceback.print_exc()

	async def run(self):
		try:
			if self.sock is None:
				server = await asyncio.start_server(self.handle_echo, self.listen_ip, self.listen_port)
				self.listen_port = server._sockets[0].getsockname()[1] #if the inital port was 0 this is giving the actual port back!
				await server.serve_forever()
			else:
				server = await asyncio.start_server(self.handle_echo, sock = self.sock)
				await server.serve_forever()
		except:
			traceback.print_exc()
			

	def run_newthread(self, soc = None):
		from threading import Thread
		import time
		if soc is not None:
			self.sock = soc

		loop = asyncio.new_event_loop()
		t = Thread(target=breakout_from_thread, args=(loop,), daemon=True)
		t.start()
		asyncio.run_coroutine_threadsafe(self.run(), loop)

		### TODO: remove this ASAP. currently it's needed to wait for the run() to start...
		time.sleep(1)
