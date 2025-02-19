# mpesa.py

import aiohttp
import asyncio
import base64
import os
from datetime import datetime
from typing import Dict, Any

class MpesaError(Exception):
    pass

class MpesaConfig:
    TESTING = os.getenv("TESTING", "false").lower() == "true"

    if TESTING:
        STK_PUSH_URL = 'https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest'
        QUERY_STATUS_URL = 'https://sandbox.safaricom.co.ke/mpesa/stkpushquery/v1/query'
        ACCESS_TOKEN_URL = 'https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials'
    else:
        STK_PUSH_URL = 'https://api.safaricom.co.ke/mpesa/stkpush/v1/processrequest'
        QUERY_STATUS_URL = 'https://api.safaricom.co.ke/mpesa/stkpushquery/v1/query'
        ACCESS_TOKEN_URL = 'https://api.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials'

    CONSUMER_KEY = os.getenv("MPESA_CONSUMER_KEY")
    CONSUMER_SECRET = os.getenv("MPESA_CONSUMER_SECRET")
    BUSINESS_SHORT_CODE = os.getenv("BUSINESS_SHORT_CODE")
    PASSKEY = os.getenv("PASSKEY")
    CALLBACK_URL = os.getenv("CALLBACK_URL")

class MpesaClient:
    @staticmethod
    async def get_access_token() -> str:
        auth = aiohttp.BasicAuth(MpesaConfig.CONSUMER_KEY, MpesaConfig.CONSUMER_SECRET)
        async with aiohttp.ClientSession(auth=auth) as session:
            async with session.get(MpesaConfig.ACCESS_TOKEN_URL) as response:
                if response.status == 200:
                    result = await response.json()
                    return result["access_token"]
                else:
                    text = await response.text()
                    raise MpesaError(f"Failed to get access token: {response.status}, {text}")

    @staticmethod
    async def initiate_stk_push(phone: str, amount: float) -> Dict[str, Any]:
        access_token = await MpesaClient.get_access_token()
        phone = process_phone_number(phone)
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        password = base64.b64encode(
            (MpesaConfig.BUSINESS_SHORT_CODE + MpesaConfig.PASSKEY + timestamp).encode()
        ).decode()

        payload = {
            'BusinessShortCode': MpesaConfig.BUSINESS_SHORT_CODE,
            'Password': password,
            'Timestamp': timestamp,
            'TransactionType': 'CustomerBuyGoodsOnline',  # or 'CustomerPayBillOnline'
            'Amount': str(int(amount)),
            'PartyA': phone,
            'PartyB': '8357056',
            'PhoneNumber': phone,
            'CallBackURL': MpesaConfig.CALLBACK_URL,
            'AccountReference': 'Sokoweb',
            'TransactionDesc': 'Payment for goods'
        }

        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {access_token}'
        }

        async with aiohttp.ClientSession() as session:
            async with session.post(MpesaConfig.STK_PUSH_URL, headers=headers, json=payload) as response:
                if response.status == 200:
                    return await response.json()
                else:
                    text = await response.text()
                    raise MpesaError(f"Failed to initiate STK Push: {response.status}, {text}")

    @staticmethod
    async def query_stk_status(checkout_request_id: str) -> Dict[str, Any]:
        access_token = await MpesaClient.get_access_token()
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        password = base64.b64encode(
            (MpesaConfig.BUSINESS_SHORT_CODE + MpesaConfig.PASSKEY + timestamp).encode()
        ).decode()

        payload = {
            'BusinessShortCode': MpesaConfig.BUSINESS_SHORT_CODE,
            'Password': password,
            'Timestamp': timestamp,
            'CheckoutRequestID': checkout_request_id
        }

        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {access_token}'
        }

        async with aiohttp.ClientSession() as session:
            async with session.post(MpesaConfig.QUERY_STATUS_URL, headers=headers, json=payload) as response:
                text = await response.text()
                try:
                    result = await response.json()
                except Exception as e:
                    raise MpesaError(f"Failed to parse STK status response: {response.status}, {text}")
                return result

def process_phone_number(phone: str) -> str:
    if phone.startswith('0'):
        phone = '254' + phone[1:]
    elif phone.startswith('+'):
        phone = phone[1:]
    return phone

# Convenience functions that match your original API
async def initiate_stk_push(phone: str, amount: float) -> Dict[str, Any]:
    """Wrapper function for backward compatibility"""
    return await MpesaClient.initiate_stk_push(phone, amount)

async def query_stk_status(checkout_request_id: str) -> Dict[str, Any]:
    """Wrapper function for backward compatibility"""
    return await MpesaClient.query_stk_status(checkout_request_id)