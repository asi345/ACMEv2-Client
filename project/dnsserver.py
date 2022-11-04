from dnslib import textwrap
from dnslib.server import DNSServer
from dnslib.zoneresolver import ZoneResolver

class DNSserver:

    def __init__(self, zone='') -> None:
        self.resolver = ZoneResolver(zone=textwrap.dedent(zone))
        self.server = DNSServer(resolver=self.resolver, address='0.0.0.0', port=10053, tcp=False)

    def start(self):
        self.server.start_thread()
    
    def stop(self):
        #self.server.thread.join()
        self.server.server.server_close()

    def setZone(self, zone):
        self.stop()
        self.resolver = ZoneResolver(zone=textwrap.dedent(zone))
        self.server = DNSServer(resolver=self.resolver, address='0.0.0.0', port=10053, tcp=False)
        self.start()