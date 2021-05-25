import hashlib
import hmac
import json
from copy import copy
from datetime import datetime, timedelta
from enum import Enum, Flag
from threading import Lock
from operator import itemgetter
from py_eth_sig_utils import utils as sig_utils
from py_eth_sig_utils.signing import v_r_s_to_signature
from random import randint
import re
import sys
from time import time, sleep
import urllib
from web3 import Web3

from trading.rest_client import RestClient, Request
from ethsnarks.eddsa import PureEdDSA, PoseidonEdDSA
from ethsnarks.field import FQ, SNARK_SCALAR_FIELD
from ethsnarks.poseidon import poseidon_params, poseidon
from v3explorer.ecdsa_utils import *
from v3explorer.eddsa_utils import *

LOOPRING_REST_HOST = 'https://api3.loopring.io'

class Security(Flag):
    NONE        = 0
    EDDSA_SIGN  = 1
    API_KEY     = 2
    ECDSA_AUTH  = 4

class SignatureType(Enum):
    ECDSA           = 0
    EDDSA           = 1
    HASH_APPROVED   = 2

class EthSignType:
    ILLEGAL     = "00"
    INVALID     = "01"
    EIP_712     = "02"
    ETH_SIGN    = "03"

class LoopringV3AmmSampleClient(RestClient):
    """
    LOOPRING REST API SAMPLE
    """

    LOOPRING_REST_HOST = LOOPRING_REST_HOST
    MAX_ORDER_ID = 1<<32

    def __init__(self, assetNames=[]):
        """"""
        super().__init__()

        self.assetNames = assetNames

        # exported account
        self.api_key     = ""
        self.address     = ""
        self.publicKeyX  = ""
        self.publicKeyY  = ""
        self.accountId   = 0

        # self.web3 = Web3(Web3.HTTPProvider(eth_addr))
        # order related
        self.orderId     = [0] * 256
        self.offchainId  = [0] * 256
        self.time_offset = 0
        self.nonce       = 0

        self.ammPoolNames = {}
        self.ammPoolAddresses = {}
        self.ammPools = {}
        self.tokenIds = {}
        self.tokenNames = {}
        self.tokenDecimals = {}
        self.withdrawalFees = {} # withdrawal fees
        self.fastWithdrawalFees = {}
        self.fastWithdrawalTokens = []

        self.init(self.LOOPRING_REST_HOST)


    def connect(self, exported_secret : dict):
        """
        Initialize connection to LOOPRING REST server.
        """
        self.accountId  = exported_secret['accountId']
        self.address    = exported_secret['address']
        self.api_key    = exported_secret['apiKey']
        self.exchange   = exported_secret['exchange']
        self.ecdsaKey   = int(exported_secret['ecdsaKey'], 16).to_bytes(32, byteorder='big')
        self.eddsaKey   = exported_secret['eddsaKey']
        self.publicKeyX = exported_secret["publicKeyX"]
        self.publicKeyY = exported_secret["publicKeyY"]
        self.chainId    = exported_secret["chainId"]

        self.next_eddsaKey = None
        self.ammJoinfeeBips = 0.0015

        # align srv and local time
        self.query_time()
        self.query_market_config()
        self.get_account()
        self.get_apiKey()
        # self.get_fees()

        for name in self.assetNames:
            #sleep(1)
            self.get_storageId(self.tokenIds[name])

        EIP712.init_env(name="Loopring Protocol",
                        version="3.6.0",
                        chainId=self.chainId,
                        verifyingContract=exported_secret['exchange'])


    def sign(self, request):
        """
        Generate LOOPRING signature.
        """
        security = request.data.pop("security", Security.NONE)
        if security == Security.NONE:
            if request.method == "POST":
                request.data = request.params
                request.params = {}
            return request

        path = request.path
        if request.params:
            if request.method in ["GET", "DELETE"]:
                path = request.path + "?" + urllib.parse.urlencode(request.params)
        else:
            request.params = dict()

        # request headers
        headers = {
            "Content-Type" : "application/json",
            "Accept"       : "application/json",
            "X-API-KEY"    : self.api_key,
        }
        if request.headers != None:
            headers.update(request.headers)

        if security & Security.EDDSA_SIGN:
            signer = UrlEddsaSignHelper(self.eddsaKey, LOOPRING_REST_HOST)
            signature = signer.sign(request)
            headers.update({"X-API-SIG": signature})
        elif security & Security.ECDSA_AUTH:
            headers.update({"X-API-SIG": request.data["X-API-SIG"]})
            pass

        request.path = path
        if request.method not in ["GET", "DELETE"]:
            request.data = json.dumps(request.data) if len(request.data) != 0 else request.params
            request.params = {}
        else:
            request.data = {}

        request.headers = headers

        # print(f"finish sign {request}")
        return request

    def query_srv_time(self):
        data = {
            "security": Security.NONE
        }

        response = self.request(
            "GET",
            headers={
                "Content-Type" : "application/json",
                "Accept"       : "application/json",
            },
            path="/api/v3/timestamp",
            data=data
        )
        json_resp = response.json()
        return json_resp['timestamp']

    def query_info(self, restPath):
        """"""
        data = {
            "security": Security.NONE
        }

        return self.request(
            "GET",
            headers={
                "Content-Type" : "application/json",
                "Accept"       : "application/json",
            },
            path="/api/v3/" + restPath,
            data=data
        ).json()

    def query_amm_pool_balance(self, poolAddress):
        """"""
        data = {
            "security": Security.NONE
        }

        return self.request(
            "GET",
            headers={
                "Content-Type" : "application/json",
                "Accept"       : "application/json",
            },
            path="/api/v3/amm/balance",
            data=data,
            params={"poolAddress": poolAddress[2:]}
        ).json()

    def query_time(self):
        """"""
        data = {
            "security": Security.NONE
        }

        data = self.perform_request(
            "GET",
            path="/api/v3/timestamp",
            data=data
        )

        local_time = int(time() * 1000)
        server_time = int(data["timestamp"])
        self.time_offset = int((local_time - server_time) / 1000)

    def query_market_config(self):
        """
            query market token and contract config
        """
        data = {"security": Security.NONE}

        params = {}

        data = self.perform_request(
            method="GET",
            path="/api/v3/exchange/tokens",
            params=params,
            data=data
        )

        for d in data:
            self.tokenIds[d['symbol']] = d['tokenId']
            self.tokenNames[d['tokenId']] = d['symbol']
            self.tokenDecimals[d['tokenId']] = d['decimals']
            if d['fastWithdrawLimit'] != '0':
                self.fastWithdrawalTokens.append(d['symbol'])

        self.query_amm_pools()

    def query_amm_pools(self):
        """"""
        data = {
            "security": Security.NONE
        }

        data = self.perform_request(
            "GET",
            path="/api/v3/amm/pools",
            data=data
        )

        # print(f"on_query_amm_pools get response: {data}")
        ammPools = data["pools"]
        for pool in ammPools:
            EIP712.init_amm_env(pool['name'], pool['version'], self.chainId, pool['address'])
            tokens = pool['tokens']['pooled']
            tokens.append(pool['tokens']['lp'])
            self.ammPools[pool['address']] = tuple(tokens)
            self.ammPoolNames[pool['name']] = pool['address']
            self.ammPoolAddresses[pool['address']] = pool['name']

    def get_account(self):
        """"""
        data = {
            "security": Security.API_KEY
        }

        data = self.perform_request(
            "GET",
            path="/api/v3/account",
            data=data,
            params = {
                "owner": self.address
            }
        )

        # print(f"on_query_account get response: {data}")
        self.nonce = data['nonce']

    def get_user_data(self, dataType, kwargs={}):
        """"""
        data = {
            "security": Security.API_KEY
        }

        params = {"accountId": self.accountId}
        for k, v in kwargs.items():
            params[k] = v

        return self.perform_request(
            "GET",
            path=f"/api/v3/user/{dataType}",
            data=data,
            params = params,
            extra=dataType
        )

    def get_transfers(self):
        """"""
        return self.get_user_data("transfers")

    def get_updates(self):
        """"""
        return self.get_user_data("updateInfo")

    def get_creates(self):
        """"""
        return self.get_user_data("createInfo")

    def get_trades(self):
        """"""
        return self.get_user_data("trades")

    def get_withdrawals(self):
        """"""
        return self.get_user_data("withdrawals")

    def get_deposits(self):
        """"""
        return self.get_user_data("deposits")

    def get_market_orderbook(self, market, level=0, limit=50):
        """"""
        params = {
            "market": market,
            "limit": limit,
            "level": level
        }

        return self.perform_request(
            "GET",
            path="/api/v3/depth",
            data={"security": Security.NONE},
            params=params,
        )

    def get_order_details(self, orderHash):
        """"""
        data = {
            "security": Security.API_KEY
        }
        params = {
            "accountId": self.accountId,
            "orderHash": orderHash
        }

        return self.perform_request(
            "GET",
            path=f"/api/v3/order",
            data=data,
            params=params,
            extra=self.accountId
        )

    def get_orders(self, start=None, end=None):
        """"""
        data = {
            "security": Security.API_KEY
        }

        params = {
            "accountId": self.accountId
        }
        if start:
            params['start'] = start
        if end:
            params['end'] = end

        return self.perform_request(
            "GET",
            path=f"/api/v3/orders",
            data=data,
            params=params,
            extra=self.accountId
        )

    def get_amm_txs(self):
        """"""
        data = {
            "security": Security.API_KEY
        }

        params = {
            "accountId": self.accountId,
        }

        return self.perform_request(
            "GET",
            path=f"/api/v3/amm/user/transactions",
            data=data,
            params = params,
            extra = self.accountId
        )

    def get_apiKey(self):
        """"""
        data = {
            "security": Security.EDDSA_SIGN
        }

        data = self.perform_request(
            "GET",
            path="/api/v3/apiKey",
            data=data,
            params = {
                "accountId": self.accountId,
            }
        )

        # print(f"on_get_apiKey get response: {data}")
        self.api_key = data["apiKey"]

    def query_balance(self):
        """"""

        data = {"security": Security.API_KEY}

        param = {
            "accountId": self.accountId,
            "tokens": ','.join([str(token) for token in self.tokenIds.values()])
        }

        return self.perform_request(
            method="GET",
            path="/api/v3/user/balances",
            params=param,
            data=data
        )

    def get_storageId(self, tokenSId):
        """"""
        data = {
            "security": Security.API_KEY
        }

        data = self.perform_request(
            "GET",
            path="/api/v3/storageId",
            data=data,
            params = {
                "accountId"     : self.accountId,
                "sellTokenId"   : tokenSId
            }
        )

        self.orderId[tokenSId] = data['orderId']
        self.offchainId[tokenSId] = data['offchainId']

        # order ids must be even
        if self.orderId[tokenSId] & 0x1 == 1:
            self.orderId[tokenSId] += 1

        # withdrawal ids must be odd
        if self.offchainId[tokenSId] & 0x1 == 0:
            self.offchainId[tokenSId] += 1

    def update_account_ecdsa(self, privateKey, publicKey):
        """"""
        self.eddsaKey = hex(int(privateKey))
        self.publicKeyX = "0x" + hex(int(publicKey.x))[2:].zfill(64)
        self.publicKeyY = "0x" + hex(int(publicKey.y))[2:].zfill(64)
        req = {
            "publicKey" : {
                "x" : self.publicKeyX,
                "y" : self.publicKeyY,
            },
            "maxFee" : {
                "tokenId" : 0,
                "volume"  : "0"
            },
            'validUntil': 1700000000,
            'nonce': self.nonce
        }
        updateAccountReq = self._create_update_request(req)
        data = {"security": Security.ECDSA_AUTH}
        data.update(updateAccountReq)

        message = createUpdateAccountMessage(updateAccountReq)
        # print(f"message hash = {bytes.hex(message)}")
        v, r, s = sig_utils.ecsign(message, self.ecdsaKey)
        data['X-API-SIG'] = "0x" + bytes.hex(v_r_s_to_signature(v, r, s)) + EthSignType.EIP_712
        data['ecdsaSignature'] = data['X-API-SIG']
        # print(f"data = {data}")

        data = self.perform_request(
            method="POST",
            path="/api/v3/account",
            params=updateAccountReq,
            data=data,
            extra=updateAccountReq
        )

        assert self.eddsaKey is not None and privateKey is not None
        self.next_eddsaKey = hex(int(privateKey))
        req = {
            "publicKey" : {
                "x" : '0x' + hex(int(publicKey.x))[2:].zfill(64),
                "y" : '0x' + hex(int(publicKey.y))[2:].zfill(64),
            },
            "maxFee" : {
                "tokenId" : 0,
                "volume"  : "4000000000000000"
            },
            'validUntil': 1700000000,
            'nonce': self.nonce
        }
        updateAccountReq = self._create_update_request(req)
        # print(f"create new order {order}")
        data = {"security": Security.ECDSA_AUTH}
        data.update(updateAccountReq)

        message = createUpdateAccountMessage(updateAccountReq)
        v, r, s = sig_utils.ecsign(message, self.ecdsaKey)
        data['X-API-SIG'] = "0x" + bytes.hex(v_r_s_to_signature(v, r, s)) + EthSignType.EIP_712

        if not approved:
            signer = UpdateAccountEddsaSignHelper(self.eddsaKey)
            signedMessage = signer.sign(updateAccountReq)
            data.update({"eddsaSignature": signedMessage})

        # print(data)
        data = self.perform_request(
            method="POST",
            path="/api/v3/account",
            params=updateAccountReq,
            data=data,
            extra=updateAccountReq
        )

        if data['status'] in ["processing", "processed"]:
            self.eddsaKey = self.next_eddsaKey
            self.next_eddsaKey = None
            publicKeyInfo = json.loads(request.data)
            self.publicKeyX = publicKeyInfo['publicKey']['x']
            self.publicKeyY = publicKeyInfo['publicKey']['y']
            print(f"on_update_account get response: {data}")

    def _create_update_request(self, req):
        """"""
        return {
            "exchange" : self.exchange,
            "owner" : self.address,
            "accountId" : self.accountId,
            "publicKey" : req['publicKey'],
            "maxFee" :  req['maxFee'],
            "validUntil" : req['validUntil'],
            "nonce" : self.nonce
        }

    def transfer_ecdsa(self, to_b, token, amount):
        """"""
        req = self._create_transfer_request(to_b, token, amount)
        # print(f"create new order {order}")
        data = {"security": Security.ECDSA_AUTH}

        data.update(req)

        message = createOriginTransferMessage(req)
        # print(f"transfer message hash = {bytes.hex(message)}")
        v, r, s = sig_utils.ecsign(message, self.ecdsaKey)
        data['X-API-SIG'] = "0x" + bytes.hex(v_r_s_to_signature(v, r, s)) + EthSignType.EIP_712
        data['ecdsaSignature'] = data['X-API-SIG']

        # print(f"data = {data}")
        return self.perform_request(
            method="POST",
            path="/api/v3/transfer",
            params=req,
            data=data,
            extra=req
        )

    def transfer_eddsa(self, to_b, token, amount, validUntil=None, storageId=None, approved=False):
        """"""
        req = self._create_transfer_request(to_b, token, amount, validUntil, storageId)
        # print(f"create new req {req}")
        data = {"security": Security.ECDSA_AUTH}
        data.update(req)

        print(req)
        exit()

        signer = OriginTransferEddsaSignHelper(self.eddsaKey)
        signedMessage = signer.sign(req)
        if not approved:
            data.update({"eddsaSignature": signedMessage})

        message = createOriginTransferMessage(req)
        # print(f"transfer message hash = {bytes.hex(message)}")
        v, r, s = sig_utils.ecsign(message, self.ecdsaKey)
        data['X-API-SIG'] = "0x" + bytes.hex(v_r_s_to_signature(v, r, s)) + EthSignType.EIP_712

        return self.perform_request(
            method="POST",
            path="/api/v3/transfer",
            params=req,
            data=data,
            extra=req
        )

    def _create_transfer_request(self, to_b, token, amount, validUntil = None, storageId = None):
        """"""

        tokenId = self.tokenIds[token]
        decimalUnit = 10**self.tokenDecimals[tokenId]

        if storageId is None:
            storageId = self.offchainId[tokenId]
            self.offchainId[tokenId] += 2

        return {
            "exchange": self.exchange,
            "payerId": self.accountId,
            "payerAddr": self.address,
            "payeeId": 0,
            "payeeAddr": to_b,
            "token": {
                "tokenId": tokenId,
                "volume": str(int(amount*decimalUnit))
            },
            "maxFee" : {
                "tokenId": tokenId,
                "volume": str(int(amount*decimalUnit/1000))
            },
            "storageId": storageId,
            "validUntil": int(time()) + 60 * 60 * 24 * 60 if validUntil is None else validUntil,
            "memo": f"test {storageId} token({tokenId}) transfer from hello_loopring"
        }

    def offchainWithdraw_ecdsa(self, token, amount, minGas=0, fastWithdrawalMode=False, feeToken='ETH'):
        """"""
        data = {"security": Security.ECDSA_AUTH}
        req = self._create_offchain_withdraw_request(token, amount, minGas, bytes(0),
                                                     fastWithdrawalMode=fastWithdrawalMode,
                                                     feeToken=feeToken)
        # print(f"create new order {order}")
        data.update(req)

        message = createOffchainWithdrawalMessage(req)
        # print(f"withdraw message hash = {bytes.hex(message)}")
        v, r, s = sig_utils.ecsign(message, self.ecdsaKey)
        data['X-API-SIG'] = "0x" + bytes.hex(v_r_s_to_signature(v, r, s)) + EthSignType.EIP_712
        data['ecdsaSignature'] = data['X-API-SIG']

        return self.perform_request(
            method="POST",
            path="/api/v3/user/withdrawals",
            params=req,
            data=data,
            extra=req
        )

    def offchainWithdraw_eddsa(self, token, amount, minGas=0,
                               extraData=bytes(0), validUntil=None, storageId=None,
                               fastWithdrawalMode=False, feeToken='ETH'):
        """"""
        data = {"security": Security.ECDSA_AUTH}
        req = self._create_offchain_withdraw_request(token, amount, minGas, extraData=extraData,
                                                     validUntil=validUntil, storageId=storageId,
                                                     fastWithdrawalMode=fastWithdrawalMode,
                                                     feeToken=feeToken)
        data.update(req)

        signer = WithdrawalEddsaSignHelper(self.eddsaKey)
        # print(f"request eddsa hash = {signer.hash(req)}")
        signedMessage = signer.sign(req)
        data.update({"eddsaSignature": signedMessage})

        message = createOffchainWithdrawalMessage(req)
        # print(f"withdraw message hash = {bytes.hex(message)}")
        v, r, s = sig_utils.ecsign(message, self.ecdsaKey)
        data['X-API-SIG'] = "0x" + bytes.hex(v_r_s_to_signature(v, r, s)) + EthSignType.EIP_712

        return self.perform_request(
            method="POST",
            path="/api/v3/user/withdrawals",
            params=req,
            data=data,
            extra=req
        )

    def _create_offchain_withdraw_request(self, token, amount: float, minGas: int,
                                          extraData=bytes(0), validUntil=None, storageId=None,
                                          fastWithdrawalMode=False, feeToken='ETH'):
        """"""
        tokenId = self.tokenIds[token]
        decimalUnit = 10**self.tokenDecimals[tokenId]
        onchainDataHash = Web3.keccak(b''.join([int(minGas).to_bytes(32, 'big'),
                                                int(self.address, 16).to_bytes(20, 'big'),
                                                extraData]))[:20]
        if storageId is None:
            storageId = self.offchainId[tokenId]
            self.offchainId[tokenId] += 2

        feeAmount = self._getWithdawalFee(token, feeToken, fastWithdrawalMode=fastWithdrawalMode)

        return {
            "exchange": self.exchange,
            "accountId": self.accountId,
            "owner": self.address,
            "token": {
                "tokenId": tokenId,
                "volume": str(int(amount*decimalUnit))
            },
            "maxFee" : {
                "tokenId": self.tokenIds[feeToken],
                "volume": feeAmount
            },
            "to": self.address,
            "onChainDataHash": "0x" + bytes.hex(onchainDataHash),
            "storageId": storageId,
            "validUntil" : int(time()) + 60 * 60 * 24 * 60 if validUntil is None else validUntil,
            "minGas": minGas,
            "extraData": bytes.hex(extraData),
            "fastWithdrawalMode": fastWithdrawalMode
        }

    def _getWithdawalFee(self, token, feeToken, fastWithdrawalMode=False):

        type = 4 if fastWithdrawalMode else 1
        response = self.get_user_data('offchainFee', kwargs={'requestType': type, 'tokenSymbol': token, 'amount': 100})

        for d in response['fees']:
            if d['token'] == feeToken:
                return d['fee']


    def send_order(self, base_token, quote_token, buy, price, amount,
            max_slippage=0.005, ammPoolAddress=None):
        order = self._create_order(base_token, quote_token, buy, price, amount, max_slippage, ammPoolAddress)
        # print(f"create new order {order}")
        data = {"security": Security.API_KEY}
        headers = {
            "Content-Type": "application/json",
        }
        data.update(order)
        return self.perform_request(
            method="POST",
            path="/api/v3/order",
            params=order,
            data=data,
            extra=order
        )

    def _create_order(self, base_token, quote_token, buy, price, amount, max_slippage, ammPoolAddress):
        if buy:
            tokenSId = self.tokenIds[quote_token]
            tokenBId = self.tokenIds[base_token]
            amountS = int(10 ** self.tokenDecimals[tokenSId] * price * amount)
            amountB = int(10 ** self.tokenDecimals[tokenBId] * amount)
        else:
            tokenSId = self.tokenIds[base_token]
            tokenBId = self.tokenIds[quote_token]
            amountS = int(10 ** self.tokenDecimals[tokenSId] * amount)
            amountB = int(10 ** self.tokenDecimals[tokenBId] * price * amount)

        # slippage only applies to AMM
        if not ammPoolAddress is None:
            amountB = int(amountB / (1 + max_slippage))

        orderId = self.orderId[tokenSId]
        assert orderId < self.MAX_ORDER_ID
        self.orderId[tokenSId] += 2

        # order base
        order = {
            # sign part
            "exchange"      : self.exchange,
            "accountId"     : self.accountId,
            "storageId"     : orderId,
            "sellToken": {
                "tokenId": tokenSId,
                "volume": str(amountS)
            },
            "buyToken" : {
                "tokenId": tokenBId,
                "volume": str(amountB)
            },
            "validUntil"    : 1700000000,
            "maxFeeBips"    : 50,
            "fillAmountBOrS": buy,
            # "taker"         : "0000000000000000000000000000000000000000",
            # aux data
            "allOrNone"     : False,
            "clientOrderId" : "SampleOrder-" + str(int(time()*1000)),
            "orderType"     : "LIMIT_ORDER"
        }

        if ammPoolAddress is not None:
            assert ammPoolAddress in self.ammPools
            assert tokenSId in self.ammPools[ammPoolAddress]
            assert tokenBId in self.ammPools[ammPoolAddress]
            order["poolAddress"] = ammPoolAddress
            order["orderType"]   = "AMM"
            order["fillAmountBOrS"] = False

        signer = OrderEddsaSignHelper(self.eddsaKey)
        msgHash = signer.hash(order)
        signedMessage = signer.sign(order)
        # update signaure
        order.update({
            "hash"     : str(msgHash),
            "eddsaSignature" : signedMessage
        })
        return order

    def cancel_order(self, **kwargs):
        """"""
        data = {
            "security": Security.EDDSA_SIGN
        }

        params = {
            "accountId": self.accountId,
        }
        if "orderHash" in kwargs:
            params['orderHash'] = kwargs['orderHash']
        elif "clientOrderId" in kwargs:
            params['clientOrderId'] = kwargs['clientOrderId']

        # print(params)
        return self.perform_request(
            method="DELETE",
            path="/api/v3/order",
            params=params,
            data=data,
        )

    def join_amm_pool(self, poolName, tokenAmounts, mintMinAmount, validUntil=None, storageIds=None, sigType=SignatureType.EDDSA):
        data = {"security": Security.API_KEY}
        req = self._create_join_pool_request(poolName, tokenAmounts, mintMinAmount, validUntil, storageIds)
        data.update(req)

        message = createAmmPoolJoinMessage(req)
        # print(f"join message hash = {bytes.hex(message)}")
        if sigType == SignatureType.ECDSA:
            v, r, s = sig_utils.ecsign(message, self.ecdsaKey)
            data['ecdsaSignature'] = "0x" + bytes.hex(v_r_s_to_signature(v, r, s)) + EthSignType.EIP_712
        elif sigType == SignatureType.EDDSA:
            signer = MessageHashEddsaSignHelper(self.eddsaKey)
            data['eddsaSignature'] = signer.sign(message)

        return self.perform_request(
            method="POST",
            path="/api/v3/amm/join",
            params=req,
            data=data,
            extra=req
        )

    def _create_join_pool_request(self, poolName, joinAmounts, mintMinAmount, validUntil = None, storageIds = None):
        poolAddress = self.ammPoolNames[poolName]
        tokenAId, tokenBId = self.ammPools[poolAddress][:2]
        poolTokenId = self.ammPools[poolAddress][2]
        mintMinAmount = str(int(mintMinAmount * 10**self.tokenDecimals.get(poolTokenId, 8)))
        req = {
            'poolAddress': poolAddress,
            'owner': self.address,
            "joinTokens" : {
                "pooled" : [
                    {
                        "tokenId": tokenAId,
                        "volume" : str(int(joinAmounts[0] * 10**self.tokenDecimals[tokenAId]))
                    },
                    {
                        "tokenId": tokenBId,
                        "volume" : str(int(joinAmounts[1] * 10**self.tokenDecimals[tokenBId]))
                    },
                ],
                "minimumLp" : {
                    "tokenId" : poolTokenId,
                    "volume"  : mintMinAmount
                }
            },
            'storageIds': [self.offchainId[tokenAId], self.offchainId[tokenBId]] if storageIds is None else storageIds,
            'validUntil': 1700000000
        }

        if storageIds is None:
            self.offchainId[tokenAId]+=2
            self.offchainId[tokenBId]+=2

            # offchain ids bust be odd
            if self.offchainId[tokenAId] & 0x1 == 0:
                self.offchainId[tokenAId] + 1
            if self.offchainId[tokenBId] & 0x1 == 0:
                self.offchainId[tokenBId] + 1

        return req

    def exit_amm_pool(self, poolName, burnAmount, exitMinAmounts, sigType=SignatureType.EDDSA):
        data = {"security": Security.API_KEY}
        req = self._create_exit_pool_request(poolName, burnAmount, exitMinAmounts)
        # print(f"create new order {order}")
        data.update(req)

        message = createAmmPoolExitMessage(req)
        # print(f"join message hash = {bytes.hex(message)}")
        if sigType == SignatureType.ECDSA:
            v, r, s = sig_utils.ecsign(message, self.ecdsaKey)
            data['ecdsaSignature'] = "0x" + bytes.hex(v_r_s_to_signature(v, r, s)) + EthSignType.EIP_712
        elif sigType == SignatureType.EDDSA:
            signer = MessageHashEddsaSignHelper(self.eddsaKey)
            data['eddsaSignature'] = signer.sign(message)

        return self.perform_request(
            method="POST",
            path="/api/v3/amm/exit",
            params=req,
            data=data,
            extra=req
        )

    def _create_exit_pool_request(self, poolName, burnAmount, exitMinAmounts):
        poolAddress = self.ammPoolNames[poolName]
        tokenAId, tokenBId = self.ammPools[poolAddress][:2]
        poolTokenId = self.ammPools[poolAddress][2]
        burnAmount = str(int(burnAmount * 10**self.tokenDecimals.get(poolTokenId, 18)))
        req = {
            'poolAddress': poolAddress,
            'owner': self.address,
            "exitTokens" : {
                "unPooled" : [
                    {
                        "tokenId": tokenAId,
                        "volume" : str(int(exitMinAmounts[0] * 10**self.tokenDecimals[tokenAId]))
                    },
                    {
                        "tokenId": tokenBId,
                        "volume" : str(int(exitMinAmounts[1] * 10**self.tokenDecimals[tokenBId]))
                    },
                ],
                "burned" : {
                    "tokenId" : poolTokenId,
                    "volume"  : burnAmount
                }
            },
            'storageId': self.offchainId[poolTokenId],
            'maxFee': str(int(int(exitMinAmounts[1])*0.002)),
            'validUntil': 1700000000
        }
        self.offchainId[poolTokenId]+=2
        return req

if __name__ == "__main__":
    loopring_rest_sample = LoopringV3AmmSampleClient()
    srv_time = loopring_rest_sample.query_srv_time()
    print(f"srv time is {srv_time}")
