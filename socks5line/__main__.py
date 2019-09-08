from socks5line.socks5line import Socks5LineProxyServer, SOCKS5Line
import asyncio

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Transparent TCP tunnel for SOCKS unaware clients.')
    parser.add_argument('proxy_connection_string', help='connection string decribing the socks5 proxy server connection properties')
    parser.add_argument('dst_ip', help='IP address of the desination server')
    parser.add_argument('dst_port', type = int, help='port number of the desination service')
    parser.add_argument('-l', '--listen-ip', default = '127.0.0.1',  help='Listener IP address to bind to')
    parser.add_argument('-p', '--listen-port', type = int, default = 11111, help='Listener port number to bind to')

    args = parser.parse_args()

    proxy = Socks5LineProxyServer.from_connection_string(args.proxy_connection_string)
    sl = SOCKS5Line(proxy, args.dst_ip, args.dst_port, listen_ip = args.listen_ip, listen_port = args.listen_port)
    asyncio.run(sl.run())