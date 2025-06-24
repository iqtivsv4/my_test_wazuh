#!/var/ossec/framework/python/bin/python3
# Wazuh - n8n integration
# Copyright (C) 2015-2025, Wazuh Inc.

import json
import sys
import time
import os
import requests

# Global vars
debug_enabled = False
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
now = time.strftime("%a %b %d %H:%M:%S %Z %Y")

# Set paths
log_file = '{0}/logs/integrations.log'.format(pwd)

def main(args):
    global debug_enabled
    # Read args
    alert_file_location = args[1]
    webhook = args[3]

    # Enable debug if fifth argument is 'debug'
    debug_enabled = (len(args) > 4 and args[4] == 'debug')

    debug("# Starting n8n integration")
    debug("# Webhook: {}".format(webhook))
    debug("# Alert file: {}".format(alert_file_location))

    # Load alert JSON
    try:
        with open(alert_file_location, 'r') as alert_file:
            json_alert = json.load(alert_file)
    except Exception as e:
        debug("Error reading alert file {}: {}".format(alert_file_location, str(e)))
        sys.exit(1)

    # Generate message
    debug("# Generating message")
    msg = generate_msg(json_alert)
    if not msg:
        debug("No message generated, skipping")
        return

    debug("# Sending message to n8n")
    send_msg(msg, webhook)

def debug(msg):
    if debug_enabled:
        msg = "{}: {}\n".format(now, msg)
        print(msg)
        with open(log_file, 'a') as f:
            f.write(msg)

def generate_msg(alert):
    # Skip alerts with level < 3 (based on ossec.conf)
    level = alert.get('rule', {}).get('level', 0)
    if level < 3:
        debug("Skipping alert with level {}".format(level))
        return None

    # Create message payload
    msg = {
        'pretext': 'WAZUH Alert',
        'title': alert.get('rule', {}).get('description', 'N/A'),
        'text': alert.get('full_log', ''),
        'rule_id': alert.get('rule', {}).get('id', 'N/A'),
        'severity': determine_severity(level),
        'timestamp': alert.get('timestamp', ''),
        'id': alert.get('id', ''),
        'all_fields': alert
    }

    return json.dumps(msg)

def determine_severity(level):
    if level <= 4:
        return 1
    elif level <= 7:
        return 2
    else:
        return 3

def send_msg(msg, url):
    try:
        headers = {'Content-Type': 'application/json', 'Accept-Charset': 'UTF-8'}
        response = requests.post(url, data=msg, headers=headers, verify=False)
        if response.status_code == 200:
            debug("Alert sent to n8n successfully")
        else:
            debug("Failed to send alert to n8n: {} - {}".format(response.status_code, response.text))
    except Exception as e:
        debug("Error sending alert to n8n: {}".format(str(e)))

if __name__ == "__main__":
    try:
        if len(sys.argv) < 4:
            debug("Error: Insufficient arguments: {}".format(sys.argv))
            sys.exit(1)

        # Log the call
        with open(log_file, 'a') as f:
            f.write("{} {}\n".format(now, " ".join(sys.argv)))

        main(sys.argv)
    except Exception as e:
        debug("Error: {}".format(str(e)))
        sys.exit(1)