from aiohttp import ClientSession
import base64, hashlib, hmac
from datetime import datetime, timezone
from collections import OrderedDict
import json, requests
from soliscloud_api import SoliscloudAPI

BASE_HEADERS = {
    'accept': 'application/json, text/plain, */*',
    'accept-language': 'en,en-US;q=0.9,nl;q=0.8,nl-NL;q=0.7,fr;q=0.6',
    'dnt': '1',
    'language': '2',
    'origin': 'https://www.soliscloud.com',
    'platform': 'Web',
    'priority': 'u=1, i',
    'referer': 'https://www.soliscloud.com/',
    'sec-ch-ua': '"Not)A;Brand";v="8", "Chromium";v="138", "Google Chrome";v="138"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'same-site',
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36',
}

def bitwise_not(bit_str):
    return ''.join(['1' if bit == '0' else '0' for bit in bit_str])

class SoliscloudWebSession:
    def __init__(self, config):
        #self.config = config
        self.key = config['key']
        self.secret = bytearray(config['secret'], 'utf-8')
        self.nmi = config['nmi']
        self.email = config["email"]
        self.password = config["password"]
        self.login_cookies = None
        self.session_token = None
        self.js_script = ""
        self.datalogger_auth_keys = {}
        self.get_js_file_and_keys()


    def login(self):
        # Use a requests session just for the login to capture cookies
        login_session = requests.Session()

        login_url = "https://www.soliscloud.com/api/user/login2"
        login_path = "/api/user/login2"

        # this value doesn't seem to matter as long as it's not empty
        login_secret_key = b'0'

        hashed_password = hashlib.md5(self.password.encode('utf-8')).hexdigest()

        payload = OrderedDict([
            ("userInfo", self.email),
            ("passWord", hashed_password),
            ("yingZhenType", 1),
            ("localTime", int(datetime.now().timestamp() * 1000)),
            ("localTimeZone", 2),
            ("language", "2")
        ])
        body_bytes = json.dumps(payload, separators=(',', ':')).encode('utf-8')

        current_time = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")
        content_md5 = base64.b64encode(hashlib.md5(body_bytes).digest()).decode('utf-8')

        string_to_sign = (f"POST\n"
                          f"{content_md5}\n"
                          f"application/json\n"
                          f"{current_time}\n"
                          f"{login_path}")
        signature = hmac.new(login_secret_key, string_to_sign.encode('utf-8'), hashlib.sha1).digest()

        encoded_signature = base64.b64encode(signature).decode('utf-8')
        auth_header = f"WEB 2424:{encoded_signature}"

        login_headers = {
            **BASE_HEADERS,
            'Authorization': auth_header,
            'Content-MD5': content_md5,
            'time': current_time,
            'content-type': 'application/json;charset=UTF-8',
        }

        try:
            response = login_session.post(login_url, headers=login_headers, data=body_bytes)
            response.raise_for_status()

            # crash out if not 400
            response_data = response.json()
            self.session_token = response_data.get("data", {}).get("token")
            self.login_cookies = login_session.cookies.get_dict()

            print("Logged in to SolisCloud...")

        except requests.exceptions.RequestException as e:
            print(f"Login request failed! Error: {e}")
            return None, None

    async def get_collector_ids(self):
        async with ClientSession() as websession:
            try:
                soliscloud = SoliscloudAPI(
                    'https://soliscloud.com:13333', websession)
                inverter_list = await soliscloud.inverter_list(
                    self.key,
                    self.secret,
                    page_no=1,
                    page_size=100,
                    #nmi_code=self.config["nmi"]  # for our Aussie brethren
                )

                collector_ids = set([self._parse_ids(d, 'collectorId') for d in inverter_list])
                return collector_ids
            except (
                    SoliscloudAPI.SolisCloudError,
                    SoliscloudAPI.HttpError,
                    SoliscloudAPI.TimeoutError,
                    SoliscloudAPI.ApiError,
            ) as error:
                print(f"Error: {error}")

    def _parse_ids(self, data, key):
        if isinstance(data, list):
            # check nested elements
            for item in data:
                return self._parse_ids(item, key)

        elif isinstance(data, dict):
            # check key in dictionary
            if key in data.keys():
                # print(data[key])
                return data[key]

            # check nested elements
            for item in data.values():
                return self._parse_ids(item, key)

    def get_js_file_and_keys(self):
        # the js file containing the info for secret keys changes from time fo time
        main_page = requests.get("https://v3.soliscloud.com/").text
        start_index = main_page.find("static/js/app.")
        end_index = main_page.find(".js", start_index)
        self.js_script = 'https://v3.soliscloud.com/' + main_page[start_index:end_index + 3]
        self.datalogger_auth_keys = self.get_keys()

    def get_keys(self):
        js = requests.get(self.js_script)
        js_code = js.text

        defaults = {}

        def get_val(string, key):
            starting_ind = string.find(key)
            end = string.find(",", starting_ind)
            val = string[starting_ind + 1:end].split("=")[-1]
            val = val.replace('"', '')
            return val

        # .prototype.$num1-4
        for i in range(1, 5):
            key = ".prototype.$num" + str(i) + "="
            val = get_val(js_code, key)
            defaults["num" + str(i)] = val

        defaults["projectType"] = get_val(js_code, ".prototype.$projectType=")
        defaults["encryptedSymbol"] = get_val(js_code, ".prototype.$encryptedSymbol=")
        defaults["encryptedSymbolSpace"] = get_val(js_code, ".prototype.$encryptedSymbolSpace=")

        return defaults

    def force_refresh(self, collector_id):
        api_url = "https://v3.soliscloud.com/api/collector/atCommandV3"
        api_path = "/collector/atCommandV3"

        payload = OrderedDict([
            ("cid", "581"),  # command ID 581 to refresh data
            ("collectorId", collector_id),
            ("localTime", int(datetime.now().timestamp() * 1000)),
            ("localTimeZone", 2),
            ("language", "2")
        ])
        body_bytes = json.dumps(payload, separators=(',', ':')).encode('utf-8')

        signed_headers = self._create_signed_headers(api_path, body_bytes)

        api_headers = {
            **BASE_HEADERS,
            **signed_headers,
            'token': self.session_token,
            'content-type': 'application/json;charset=UTF-8',
        }

        try:
            response = requests.post(api_url, headers=api_headers, data=body_bytes, cookies=self.login_cookies)
            response.raise_for_status()
            print("API call successful.")
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"API call failed, error: {e}")
            if hasattr(e, 'response') and e.response is not None:
                print(f"Status: {e.response.status_code}, Response: {e.response.text}")
            return None

    def _create_signed_headers(self, path, body_bytes):
        # Preliminaries for auth key
        keys = self.datalogger_auth_keys
        verb = "POST"
        current_time = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")
        content_md5 = base64.b64encode(hashlib.md5(body_bytes).digest()).decode('utf-8')

        key_id = str(int(bitwise_not(keys["num1"]), 2))
        part2 = str(int(bitwise_not(keys["num2"]), 2))
        part3 = hex(int(bitwise_not(keys["num3"]), 2))[2:]
        part4 = hex(int(bitwise_not(keys["num4"]), 2))[2:]
        secret_key = (part2 + part3 + part4).encode('utf-8')

        # encoding
        string_to_sign = f"{verb.upper()}\n{content_md5}\napplication/json\n{current_time}\n{path}"

        signature = hmac.new(secret_key, string_to_sign.encode('utf-8'), hashlib.sha1).digest()
        encoded_signature = base64.b64encode(signature).decode('utf-8')
        auth_header = (f"{keys["projectType"]}"
                       f"{keys["encryptedSymbolSpace"]}"
                       f"{key_id}"
                       f"{keys["encryptedSymbol"]}"
                       f"{encoded_signature}")

        return {
            'Authorization': auth_header,
            'Content-MD5': content_md5,
            'time': current_time,
        }