from datetime import datetime, timedelta
import re
import time
import json
import jwt

import httpx

from .const import (
    API_KEY_AUTHENTICATION,
    API_KEY_CUSTOMER_SERVICES,
    API_KEY_HOLIDAYS_USER_BY_ADDRESS,
    API_KEY_USER_ACCOUNTS,
    REST_API_URL,
)
from .Entities import AccountInfo, Service

ASYNC_TIMEOUT = 30
SYNC_TIMEOUT = 10

NOT_DELAYED_REGEX = re.compile("service will not be delayed")
DELAY_REGEX = re.compile("delayed .+?(?P<quanity>[^ ]+) day")
MONTHS = [
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December"
]


def date_range_regex(month: str) -> re.Pattern:
    next_month = MONTHS.index(month)
    return re.compile("(?P<start>" + month + " \d+).+?(?P<end>(" + month + " \d+)|(" + MONTHS[next_month] + " \d+))")


def impacted_dates(message: str, holiday: datetime):
    if NOT_DELAYED_REGEX.search(message) or datetime.now().year - holiday.year > 2:
        return {}
    month = holiday.strftime("%B")
    matches = date_range_regex(month).search(message)
    if not matches:
        return {}
    end_group = matches.group("end")
    if month == "December" and "January" in end_group:
        end = datetime.strptime(f"{end_group} {holiday.year + 1}", "%B %d %Y")
    else:
        end = datetime.strptime(f"{end_group} {holiday.year}", "%B %d %Y")
    dates = end - holiday
    matches = DELAY_REGEX.search(message)
    if not matches:
        delay = 1
    else:
        delay = 1 if matches.group("quanity") == "one" else 2
    
    return {
        d: d + timedelta(days=delay)
        for d in [holiday + timedelta(days=i) for i in range(0, dates.days)]
    }


class WMClient:
    def __init__(self, email, password, client_session=None):
        self.email = email
        self.password = password
        self._session_token = None
        self._access_token = None
        self._refresh_token = None
        self._id_token = None
        self._user_id = None
        self._token_expires_time = None
        self._okta_access_token = None
        self._client_id = None
        self._issuer = None
        self._holiday_regex = re.compile("(\d{1,2}/\d{1,2}(?:/\d{2,4})?)")
        self._delay_regex = re.compile("(\d+)(?: day)? delay")
        self._access_token_regex = re.compile(
            "access_token\s*=\s*'(.+?)'", re.MULTILINE
        )
        self._client_session = client_session or httpx.AsyncClient()

    def __string_escape(self, input: str, encoding="utf-8"):
        return (
            input.encode("latin1")
            .decode("unicode-escape")
            .encode("latin1")
            .decode(encoding)
        )

    def __set_token_data(self, response_data):
        self._session_token = response_data["sessionToken"]
        self._access_token = response_data["access_token"]
        self._refresh_token = response_data["refresh_token"]
        self._id_token = response_data["id_token"]
        self._user_id = response_data["id"]
        self._token_expires_time = time.time() + response_data["expires_in"]
        decoded_jwt = jwt.decode(
            response_data["access_token"], options={"verify_signature": False}
        )
        self._client_id = decoded_jwt["cid"]
        self._issuer = decoded_jwt["iss"]

    async def async_authenticate(self):
        self._apiKey = API_KEY_AUTHENTICATION
        data = await self.async_api_post(
            "user/authenticate",
            {"username": self.email, "password": self.password, "locale": "en_US"},
        )
        self.__set_token_data(data["data"])

        return data

    def authenticate(self):
        self._apiKey = API_KEY_AUTHENTICATION
        data = self.api_post(
            "user/authenticate",
            {"username": self.email, "password": self.password, "locale": "en_US"},
        )
        self.__set_token_data(data["data"])

        return data

    async def async_okta_authorize(self):
        # get from access token issuer
        client = self._client_session
        response = await client.get(
            self._issuer + "/v1/authorize",
            params={
                "client_id": self._client_id,
                "nonce": "x",
                "prompt": "none",
                "response_mode": "okta_post_message",
                "response_type": "token",
                "state": "x",
                "scope": "openid email offline_access",
                "redirect_uri": "https://www.wm.com",
                "sessionToken": self._session_token,
            },
            timeout=ASYNC_TIMEOUT,
        )
        response.raise_for_status()
        result = re.search(self._access_token_regex, response.text)
        self._okta_access_token = self.__string_escape(result.group(1))

    def okta_authorize(self):
        # get from access token issuer
        client = httpx.Client()
        response = client.get(
            self._issuer + "/v1/authorize",
            params={
                "client_id": self._client_id,
                "nonce": "x",
                "prompt": "none",
                "response_mode": "okta_post_message",
                "response_type": "token",
                "state": "x",
                "scope": "openid email offline_access",
                "redirect_uri": "https://www.wm.com",
                "sessionToken": self._session_token,
            },
            timeout=SYNC_TIMEOUT,
        )
        response.raise_for_status()
        result = re.search(self._access_token_regex, response.text)
        self._okta_access_token = self.__string_escape(result.group(1))

    async def async_get_accounts(self):
        self._apiKey = API_KEY_USER_ACCOUNTS
        jsonData = await self.async_api_get(
            f"authorize/user/{self._user_id}/accounts",
            {"timestamp": time.time() * 1000, "lang": "en_US"},
        )

        results = []
        for acct in jsonData["data"]["linkedAccounts"]:
            results.append(AccountInfo(acct))
        return results

    def get_accounts(self):
        self._apiKey = API_KEY_USER_ACCOUNTS

        jsonData = self.api_get(
            f"authorize/user/{self._user_id}/accounts",
            {"timestamp": time.time() * 1000, "lang": "en_US"},
        )

        results = []
        for acct in jsonData["data"]["linkedAccounts"]:
            results.append(AccountInfo(acct))
        return results

    async def async_get_services(self, account_id):
        self._apiKey = API_KEY_CUSTOMER_SERVICES
        jsonData = await self.async_api_get(
            f"account/{account_id}/services",
            {
                "lang": "en_US",
                "serviceChangeEligibility": "Y",
                "userId": self._user_id,
            },
        )
        results = []
        for svc in jsonData["services"]:
            results.append(Service(svc))

        return results

    def get_services(self, account_id):
        self._apiKey = API_KEY_CUSTOMER_SERVICES

        jsonData = self.api_get(
            f"account/{account_id}/services",
            {
                "lang": "en_US",
                "serviceChangeEligibility": "Y",
                "userId": self._user_id,
            },
        )
        results = []
        for svc in jsonData["services"]:
            results.append(Service(svc))

        return results

    async def async_get_service_pickup(self, account_id, service_id):
        self._apiKey = API_KEY_CUSTOMER_SERVICES

        jsonData = await self.async_api_get(
            f"account/{account_id}/service/{service_id}/pickupinfo",
            {"lang": "en_US", "checkAlerts": "Y", "userId": self._user_id},
        )

        holiday_info = await self.async_get_holidays(account_id, holiday_type="all")
        
        pickupDates = []
        for dateStr in jsonData["pickupScheduleInfo"]["pickupDates"]:
            date = datetime.strptime(dateStr, "%m-%d-%Y")
            if date in holiday_info.keys():
                date = holiday_info[date]
            pickupDates.append(date)

        return pickupDates

    def get_service_pickup(self, account_id, service_id):
        self._apiKey = API_KEY_CUSTOMER_SERVICES

        jsonData = self.api_get(
            f"account/{account_id}/service/{service_id}/pickupinfo",
            {"lang": "en_US", "checkAlerts": "Y", "userId": self._user_id},
        )

        holiday_info = self.get_holidays(account_id, holiday_type="all")

        pickupDates = []
        for dateStr in jsonData["pickupScheduleInfo"]["pickupDates"]:
            date = datetime.strptime(dateStr, "%m-%d-%Y")
            if date in holiday_info.keys():
                date = holiday_info[date]
            pickupDates.append(date)

        return pickupDates

    async def async_get_holidays(self, account_id, holiday_type="upcoming"):
        self._apiKey = API_KEY_HOLIDAYS_USER_BY_ADDRESS

        jsonData = await self.async_api_get(
            f"user/{self._user_id}/account/{account_id}/holidays",
            {"lang": "en_US", "type": holiday_type},
        )

        holidays = {}

        if "holidayData" in jsonData:
            for holiday in jsonData["holidayData"]:
                holiday_message = holiday["holidayHours"]
                holiday_date = str(holiday["holidayDate"])
                holidays.update(impacted_dates(holiday_message, datetime.strptime(holiday_date, "%Y-%m-%d")))
         #       holidays.update(self.__parse_holiday_impacted_dates(holiday_message))
        return holidays

    def get_holidays(self, account_id, holiday_type="upcoming"):
        self._apiKey = API_KEY_HOLIDAYS_USER_BY_ADDRESS

        jsonData = self.api_get(
            f"user/{self._user_id}/account/{account_id}/holidays",
            {"lang": "en_US", "type": holiday_type},
        )

        holidays = {}

        if "holidayData" in jsonData:
            for holiday in jsonData["holidayData"]:
                holiday_message = holiday["holidayHours"]
                holiday_date = str(holiday["holidayDate"])
                holidays.update(impacted_dates(holiday_message, datetime.strptime(holiday_date, "%Y-%m-%d")))
        #        holidays.update(self.__parse_holiday_impacted_dates(holiday_message))
        return holidays

    async def async_api_get(self, path="", query=None):
        """Execute an API get asynchronously"""
        client = self._client_session
        response = await client.get(
            REST_API_URL + path,
            params=query,
            headers=self.headers,
            timeout=ASYNC_TIMEOUT,
        )
        response.raise_for_status()
        return json.loads(response.content.decode("UTF-8"))

    def api_get(self, path="", query=None):
        """Execute an API get synchronously"""
        client = httpx.Client()
        response = client.get(
            REST_API_URL + path,
            params=query,
            headers=self.headers,
            timeout=SYNC_TIMEOUT,
        )
        response.raise_for_status()
        return json.loads(response.content.decode("UTF-8"))

    def api_post(self, path="", data=None):
        """Execute an API post synchronously"""
        client = httpx.Client()
        response = client.post(
            REST_API_URL + path,
            headers=self.headers,
            json=data,
            timeout=SYNC_TIMEOUT,
        )
        response.raise_for_status()

        return json.loads(response.content.decode("UTF-8"))

    async def async_api_post(self, path="", data=None):
        """Execute an API post asynchronously"""
        client = self._client_session
        response = await client.post(
            REST_API_URL + path,
            headers=self.headers,
            json=data,
            timeout=ASYNC_TIMEOUT,
        )
        response.raise_for_status()
        return json.loads(response.content.decode("UTF-8"))

    def __get_holiday_delay_date(self, jsonData):
        if "pickupDayInfo" in jsonData:
            jsonNode = jsonData["pickupDayInfo"]
            if "message" in jsonNode and jsonNode["message"] is not None:
                # The only way to tell if the date is impacted by a holiday is via the message string
                if "HOLIDAY" in jsonNode["message"].upper():
                    date_str = jsonNode["date"]
                    return datetime.strptime(date_str, "%m-%d-%Y")
        return None

    @property
    def headers(self):
        headers = {"Content-Type": "application/json", "apiKey": self._apiKey}

        if self._okta_access_token is not None:
            headers["oktaToken"] = self._okta_access_token

        return headers
