"""
This forces the datalogger to refresh certain data once immediately. The data can then be polled
locally from the datalogger's web page (/inverter.cgi), which returns [serial number, firmware version, inverter model,
inverter temperature, current power, yield today, total yield, alerts flag].
"""

import asyncio  # for original soliscloud_api
import json
from web_classes.soliscloud_global import SoliscloudWebSession
from web_classes.soliscloud_local import LocalSession
import time

if __name__ == "__main__":
    with open("config.json") as f:
        config = json.load(f)

    # Initial setup and login to soliscloud.com
    web_session = SoliscloudWebSession(config)
    web_session.login()

    # Pull collector ID from API. Hardcode this if you want to avoid repeated API calls.
    c_ids = list(asyncio.run(web_session.get_collector_ids()))

    # Send refresh command via website
    web_session.force_refresh(c_ids[0])

    # Give inverter some time to update and output latest power
    time.sleep(1)
    local_session = LocalSession(config, autorefresh=True)  # refresh on every call
    print("Generated power: {} W".format(local_session.get_val("current_power")))
