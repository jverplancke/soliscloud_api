import requests
import unicodedata

class LocalSession:
    def __init__(self, config, autorefresh=True):
        self.username = 'admin'
        self.password = config["datalogger_password"]
        self.address = config["datalogger_IP"]
        self.cgi_url = "http://" + self.address + "/inverter.cgi"
        self.autorefresh = autorefresh
        self.latest = {}

    def refresh(self):
        response = requests.get(
            self.cgi_url,
            auth=requests.auth.HTTPBasicAuth(self.username, self.password),
        )
        if response.status_code == 200:
            response_text = unicodedata.normalize('NFKD', response.text)
            vals = response_text.encode('ascii', 'ignore').decode('ascii').split(";")
            keys = ["serial_no",
                    "firmware_version",
                    "inverter_model",
                    "inverter_temperature",
                    "current_power",
                    "yield_today",
                    "total_yield",
                    "alerts"]
            data_dict = {}

            for k, v in zip(keys, vals):
                data_dict[k] = v

            self.latest = data_dict

    def get_val(self, key):
        if self.autorefresh: self.refresh()

        return self.latest[key]
