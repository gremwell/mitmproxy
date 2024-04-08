"""
Example:

    > mitmdump -s ./mitmproxy/contrib/flowmux/flowmux.py
    
    > mitmdump -s ./mitmproxy/contrib/flowmux/flowmux.py --set param1 test

    Run a transparent TCP relay, just for testing:
    > socat -v TCP4-LISTEN:4444,reuseaddr,fork TCP4:www.gremwell.com:443

    The following gets redirected (curl of MacOS matches the hardcoded JA3 hash value below):
    > curl --proxy http://localhost:8080 https://www.gremwell.com

    The following goes through (JA3 hash does not match):
    > curl --ciphers ECDHE-RSA-AES256-GCM-SHA384 --proxy http://localhost:8080 https://www.gremwell.com

    XXX The following causes an exception and the connection goes through:
    > curl --ciphers TLS_AES_256_GCM_SHA384 --proxy http://localhost:8080 https://www.gremwell.com
"""
import struct
import hashlib

from mitmproxy import connection
from mitmproxy import ctx
from mitmproxy import tls
from mitmproxy.proxy import events
from mitmproxy.proxy import commands
from mitmproxy.addonmanager import Loader


class FlowmuxRedirectAction:
    def __init__(self, server_address):
        self.server_address = server_address

        def __repr__(self):
            return f"FlowmuxRedirectAction({self.server_address})"


class FlowmuxPassthroughAction:
    def __repr__(self):
        return "FlowmuxPassthroughAction()"


class FlowmuxStrategy:
    def __init__(self):
        self.target_list = [('127.0.0.1', 4444)] # FIXME just for testing see above
        self.target_ja3 = "070ed1ebe4979528bf846db0c1382e79"  # FIXME curl on MacOS

    @staticmethod
    def calc_ja3(data: tls.ClientHelloData):
        version = data.client_hello._client_hello.version
        # TLSVersion
        ja3_full = [str((version.major << 8) | version.minor)]

        # Ciphers
        # first is Reserved
        ja3_full.append(
            '-'.join(map(str, data.client_hello.cipher_suites[1:])))

        # Extensions
        # first is Reserved
        extensions = list(zip(*data.client_hello.extensions))[0]
        ja3_full.append('-'.join(map(str, extensions[1:])))

        extensions_dict = dict(data.client_hello.extensions)

        def parse_list(data, len_fmt, data_fmt):
            offset = struct.calcsize(len_fmt)
            size = struct.unpack_from(len_fmt, data)[0]
            num = size//struct.calcsize(data_fmt)
            return struct.unpack_from(f">{num}{data_fmt}", data, offset)

        # EllipticCurves
        # first is Reserved
        supported_groups = extensions_dict[10]
        ja3_full.append(
            '-'.join(map(str, parse_list(supported_groups, ">H", "H")[1:])))

        # EllipticCurvePointFormats
        ec_point_formats = extensions_dict[11]
        ja3_full.append(
            '-'.join(map(str, parse_list(ec_point_formats, ">B", "B"))))

        ja3_full_str = ','.join(ja3_full)

        ja3 = hashlib.md5(ja3_full_str.encode()).hexdigest()
        return ja3, ja3_full_str

    def get_proxy_action_on_tls_clienthello(self,
                                            client_address: connection.Address,
                                            server_address: connection.Address,
                                            client_hello_data):
        ja3, ja3_full_str = self.calc_ja3(client_hello_data)
        assert ja3 != None

        ctx.log(f"client_address {client_address}, server_address {server_address}, ja3 {ja3}")

        if len(self.target_list) > 0 and self.target_ja3 == ja3:
            action = FlowmuxRedirectAction(self.target_list[-1])
        else:
            action = FlowmuxPassthroughAction()

        ctx.log(f"action {action}")
        return action

    def handle_error(self, address, error):
        ctx.log("handle_error invoked")

        def is_connection_refused(error):
            return "Errno 61" in error or "Errno 111" in error

        if self.target_list and address == self.target_list[-1] and is_connection_refused(error):
            ctx.log("... connection refused")
            self.target_list.pop()


class FlowMux:
    def __init__(self):
        outer_class_self = self

        class HookedOpenConnectionCompleted(events.OpenConnectionCompleted):
            def __init__(self, command: commands.OpenConnection, *argv, **kwargv):
                if command.connection.error != None:
                    outer_class_self.handle_error(
                        command.connection.address, command.connection.error)

                super().__init__(command, *argv, **kwargv)

        events.OpenConnectionCompleted = HookedOpenConnectionCompleted

    @staticmethod
    def get_addr(server: connection.Server):
        # .peername may be unset in upstream proxy mode, so we need a fallback.
        return server.peername or server.address

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
        # if "tls_strategy" not in updated:
        #     return
        # if ctx.options.tls_strategy > 0:
        #     self.strategy = ProbabilisticStrategy(ctx.options.tls_strategy / 100)
        # else:
        #     self.strategy = ConservativeStrategy()

        # TODO pass via parameters
        self.strategy = FlowmuxStrategy()

    def tls_clienthello(self, data: tls.ClientHelloData):
        client_address = data.context.client.peername[:2]
        server_address = self.get_addr(data.context.client)[:2]

        action = self.strategy.get_proxy_action_on_tls_clienthello(
            client_address, server_address, data)

        data.ignore_connection = True  # ???
        if isinstance(action, FlowmuxRedirectAction):
            data.context.server = connection.Server(
                address=action.server_address)
        else:
            assert isinstance(action, FlowmuxPassthroughAction)

    def handle_error(self, address, error):
        self.strategy.handle_error(address, error)


addons = [FlowMux()]
