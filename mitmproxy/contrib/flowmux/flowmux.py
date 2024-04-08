"""
Example:

    > mitmdump -s tls_multiplexer.py
    
    > mitmdump -s tls_multiplexer.py --set param1 test

    > curl --proxy http://localhost:8080 https://example.com

"""
import struct
import hashlib

from mitmproxy import connection
from mitmproxy import ctx
from mitmproxy import tls
from mitmproxy.proxy import events
from mitmproxy.proxy import commands
from mitmproxy.addonmanager import Loader
               
class TlsMultiplexer:
    def __init__(self):
        outer_class_self = self
        
        class HookedOpenConnectionCompleted(events.OpenConnectionCompleted):
            def __init__(self,command: commands.OpenConnection,*argv,**kwargv):
                if command.connection.error != None:
                    outer_class_self.handle_error(command.connection.address,command.connection.error)

                super().__init__(command,*argv,**kwargv)

        events.OpenConnectionCompleted = HookedOpenConnectionCompleted


    @staticmethod
    def get_addr(server: connection.Server):
        # .peername may be unset in upstream proxy mode, so we need a fallback.
        return server.peername or server.address

    @staticmethod
    def calc_ja3(data: tls.ClientHelloData):
        version = data.client_hello._client_hello.version        
        #TLSVersion
        ja3_full = [str((version.major<<8) | version.minor)]
        
        #Ciphers
        #first is Reserved
        ja3_full.append('-'.join(map(str,data.client_hello.cipher_suites[1:])))
        
        #Extensions
        #first is Reserved
        extensions = list(zip(*data.client_hello.extensions))[0]
        ja3_full.append('-'.join(map(str,extensions[1:])))
        
        extensions_dict = dict(data.client_hello.extensions)
        
        def parse_list(data,len_fmt,data_fmt):
            offset = struct.calcsize(len_fmt)
            size = struct.unpack_from(len_fmt,data)[0]
            num = size//struct.calcsize(data_fmt)
            return struct.unpack_from(f">{num}{data_fmt}",data,offset)
        
        #EllipticCurves
        #first is Reserved
        supported_groups = extensions_dict[10]
        ja3_full.append('-'.join(map(str,parse_list(supported_groups,">H","H")[1:])))
        
        #EllipticCurvePointFormats
        ec_point_formats = extensions_dict[11]
        ja3_full.append('-'.join(map(str,parse_list(ec_point_formats,">B","B"))))
        
        ja3_full_str = ','.join(ja3_full)
        
        ja3 = hashlib.md5(ja3_full_str.encode()).hexdigest()
        return ja3,ja3_full_str


    def load(self, loader: Loader):
        '''
        loader.add_option(
            name="ja3",
            typespec=Optional[str],
            default=None,
            help="ja3",
        )

        loader.add_option(
            name="redirect_ports",
            typespec=Optional[str],
            default=None,
            help="redirect_ports",
        )
        '''
        pass
        

        
    def configure(self, updated):
        #if "redirect" not in updated:
        #    return
        
        #TODO pass via parameters
        self.target_list = [('127.0.0.1',4444)]
        self.target_ja3 = None

    def tls_clienthello(self, data: tls.ClientHelloData):
        ja3,ja3_full_str = self.calc_ja3(data)
        assert ja3 != None
        addr,port = self.get_addr(data.context.client)[:2]
        
        print(addr, port, ja3, ja3_full_str)
        
        data.ignore_connection = True
        if len(self.target_list) > 0 and self.target_ja3 == ja3:
            data.context.server = connection.Server(address=self.target_list[-1])
        
    def handle_error(self,address,error):
        if self.target_list and address == self.target_list[-1] and "Errno 111" in error:
            print("connection refused")
            self.target_list.pop()

addons = [TlsMultiplexer()]
