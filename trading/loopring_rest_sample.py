"""
REST API Sample for Loopring Crypto Exchange.
"""
import hashlib
import json
from enum import Enum
from time import time, sleep
import urllib

from trading.rest_client import RestClient, Request
from ethsnarks.eddsa import PureEdDSA, PoseidonEdDSA
from ethsnarks.field import FQ, SNARK_SCALAR_FIELD
from ethsnarks.poseidon import poseidon_params, poseidon


class Security(Enum):
    NONE = 0
    SIGNED = 1
    API_KEY = 2


class LoopringRestApiSample(RestClient):
    """
    LOOPRING REST API SAMPLE
    """

    LOOPRING_REST_HOST   = "https://api.loopring.io"
    MAX_ORDER_ID = 1_000_000

    market_info_map = {
        "ETH"  : {"tokenId":0, "symbol":"ETH",  "decimals":18},
        "LRC"  : {"tokenId":2, "symbol":"LRC",  "decimals":18},
        "USDT" : {"tokenId":3, "symbol":"USDT", "decimals":6},
        "DAI"  : {"tokenId":5,"symbol":"DAI","decimals":18}
    }

    def __init__(self, api_key, exchangeId, private_key, address, accountId):
        """"""
        super().__init__()
        # exported account
        self.api_key     = api_key
        self.exchangeId  = exchangeId
        self.private_key = private_key
        self.address     = address
        self.accountId   = accountId
        self.restData    = {"security": Security.NONE}
        self.restHeader  = {'X-API-KEY': self.api_key}

        # order related
        self.orderId     = [None] * 256
        self.time_offset = 0
        self.order_sign_param = poseidon_params(SNARK_SCALAR_FIELD, 14, 6, 53, b'poseidon', 5, security_target=128)

        self.init(self.LOOPRING_REST_HOST)
        self.connect()

    def connect(self):
        """
        Initialize connection to LOOPRING REST server.
        """
        # align srv and local time
        self.query_time()
        for token_id in [info['tokenId'] for info in self.market_info_map.values()]:
            self.query_orderId(token_id)
        #sleep(8)

    def get_exchange_configuration(self):
        """
        Get general exchange info
        """

        return self.perform_request(
            method="GET",
            path="/api/v2/exchange/info",
            data=self.restData
        )

    def get_market_configuration(self):
        """
        Get market info
        """

        return self.perform_request(
            method="GET",
            path="/api/v2/exchange/markets",
            data=self.restData
        )

    def get_token_configuration(self):
        """
        Get token info
        """

        return self.perform_request(
            method="GET",
            path="/api/v2/exchange/tokens",
            data=self.restData
        )

    def get_market_orderbook(self, market, level, limit=50):
        """
        Get orderbook
        """

        params = {
            'market': market,
            'level': level,
            'limit': limit
        }
        return self.perform_request(
            method="GET",
            path="/api/v2/depth",
            data=self.restData,
            params=params
        )

    def get_user_exchange_balances(self, accountId, tokens):
        """
        Get account balance
        """

        params = {
            'accountId': accountId
        }
        return self.perform_request(
            method="GET",
            path="/api/v2/user/balances",
            data=self.restData,
            params=params,
            headers=self.restHeader
        )

    def get_order_details(self, accountId, orderHash):

        params = {
            'accountId': accountId,
            'orderHash': orderHash
        }
        return self.perform_request(
            method="GET",
            path="/api/v2/order",
            data=self.restData,
            params=params,
            headers=self.restHeader
        )

    def get_multiple_orders(self, accountId, start, end, market=None, limit=50):

        params = {
            'accountId': accountId,
            'start': start,
            'end': end,
            'limit': limit,
        }
        if not market is None:
            params['market'] = market

        return self.perform_request(
            method="GET",
            path="/api/v2/orders",
            data=self.restData,
            params=params,
            headers=self.restHeader
        )

    def buy(self, base_token, quote_token, price, volume):
        """
        Place buy order
        """
        return self._order(base_token, quote_token, True, price, volume)

    def sell(self, base_token, quote_token, price, volume):
        """
        Place sell order
        """
        return self._order(base_token, quote_token, False, price, volume)

    def cancel_order(self, **cancel_params):
        """"""
        data = {
            "security": Security.SIGNED
        }

        params = {
            "accountId": self.accountId,
        }

        if "clientOrderId" in cancel_params:
            params["clientOrderId"] = cancel_params["clientOrderId"]
        if "orderHash" in cancel_params:
            params["orderHash"] = cancel_params["orderHash"]

        print(f"cancel_order {params}")
        return self.perform_request(
            method="DELETE",
            path="/api/v2/orders",
            params=params,
            data=data
        )

    def _order(self, base_token, quote_token, buy, price, volume):
        if buy:
            tokenS = self.market_info_map[quote_token]
            tokenB = self.market_info_map[base_token]
            amountS = str(int(10 ** tokenS['decimals'] * price * volume))
            amountB = str(int(10 ** tokenB['decimals'] * volume))
        else:
            tokenS = self.market_info_map[base_token]
            tokenB = self.market_info_map[quote_token]
            amountS = str(int(10 ** tokenS['decimals'] * volume))
            amountB = str(int(10 ** tokenB['decimals'] * price * volume))

        tokenSId = tokenS['tokenId']
        tokenBId = tokenB['tokenId']

        orderId = self.orderId[tokenSId]
        assert orderId < self.MAX_ORDER_ID
        self.orderId[tokenSId] += 1

        # make valid time ahead 1 hour
        validSince = int(time()) - self.time_offset - 3600

        # order base
        order = {
            "exchangeId"    : self.exchangeId,
            "orderId"       : orderId,
            "accountId"     : self.accountId,
            "tokenSId"      : tokenSId,
            "tokenBId"      : tokenBId,
            "amountS"       : amountS,
            "amountB"       : amountB,
            "allOrNone"     : "false",
            "validSince"    : validSince,
            "validUntil"    : validSince + 30 * 24 * 60 * 60,
            "maxFeeBips"    : 50,
            "label"         : 211,
            "buy"           : "true" if buy else "false",
            "clientOrderId" : "SampleOrder" + str(int(time()))
        }

        order_message = self._serialize_order(order)
        msgHash = poseidon(order_message, self.order_sign_param)
        signedMessage = PoseidonEdDSA.sign(msgHash, FQ(int(self.private_key)))
        # update signaure
        order.update({
            "hash"        : str(msgHash),
            "signatureRx" : str(signedMessage.sig.R.x),
            "signatureRy" : str(signedMessage.sig.R.y),
            "signatureS"  : str(signedMessage.sig.s)
        })

        # print(f"create new order {order}")
        data = {"security": Security.SIGNED}
        return self.perform_request(
            method="POST",
            path="/api/v2/order",
            params=order,
            data=data,
            extra=order
        )

    def sign(self, request):
        """
        Generate LOOPRING signature.
        """
        security = request.data["security"]
        if security == Security.NONE:
            if request.method == "POST":
                request.data = request.params
                request.params = {}
            return request

        if request.params:
            path = request.path + "?" + urllib.parse.urlencode(request.params)
        else:
            request.params = dict()
            path = request.path

        # request headers
        headers = {
            "Content-Type" : "application/x-www-form-urlencoded",
            "Accept"       : "application/json",
            "X-API-KEY"    : self.api_key,
        }

        if security == Security.SIGNED:
            ordered_data = self._encode_request(request)
            hasher = hashlib.sha256()
            hasher.update(ordered_data.encode('utf-8'))
            msgHash = int(hasher.hexdigest(), 16) % SNARK_SCALAR_FIELD
            signed = PoseidonEdDSA.sign(msgHash, FQ(int(self.private_key)))
            signature = ','.join(str(_) for _ in [signed.sig.R.x, signed.sig.R.y, signed.sig.s])
            headers.update({"X-API-SIG": signature})

        request.path = path
        if request.method != "GET":
            request.data = request.params
            request.params = {}
        else:
            request.data = {}

        request.headers = headers

        # print(f"finish sign {request}")
        return request

    def _encode_request(self, request):
        method = request.method
        url = urllib.parse.quote(self.LOOPRING_REST_HOST + request.path, safe='')
        data = urllib.parse.quote("&".join([f"{k}={str(v)}" for k, v in request.params.items()]), safe='')
        return "&".join([method, url, data])

    def query_srv_time(self):
        data = {
            "security": Security.NONE
        }

        response = self.request(
            "GET",
            path="/api/v2/timestamp",
            data=data
        )
        json_resp = response.json()
        if json_resp['resultInfo']['code'] != 0:
            raise AttributeError(f"on_query_time failed {data}")
        return json_resp['data']

    def query_time(self):
        """"""
        data = {
            "security": Security.NONE
        }
        data = self.perform_request(
            "GET",
            path="/api/v2/timestamp",
            data=data
        )
        if data['resultInfo']['code'] != 0:
            raise AttributeError(f"on_query_time failed {data}")
        local_time = int(time() * 1000)
        server_time = int(data["data"])
        self.time_offset = int((local_time - server_time) / 1000)

    def query_orderId(self, tokenId):
        """"""
        data = {
            "security": Security.API_KEY
        }
        params = {
            "accountId": self.accountId,
            "tokenSId": tokenId
        }
        data = self.perform_request(
            method="GET",
            path="/api/v2/orderId",
            params=params,
            data=data
        )

        if data['resultInfo']['code'] != 0:
            raise AttributeError(f"on_query_orderId failed {data}")

        self.orderId[tokenId] = int(data['data'])

    def _serialize_order(self, order):
        return [
            int(order["exchangeId"]),
            int(order["orderId"]),
            int(order["accountId"]),
            int(order["tokenSId"]),
            int(order["tokenBId"]),
            int(order["amountS"]),
            int(order["amountB"]),
            int(order["allOrNone"] == 'true'),
            int(order["validSince"]),
            int(order["validUntil"]),
            int(order["maxFeeBips"]),
            int(order["buy"] == 'true'),
            int(order["label"])
        ]
