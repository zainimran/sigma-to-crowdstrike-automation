import yaml
import requests
import json
import sys
import os

with open('config.yml', 'r') as stream:
    try:
        data_loaded = yaml.safe_load(stream)
        client_list = list(data_loaded.keys())
        for client in client_list:
            if data_loaded[client]['cs_base_url'] is None:
                continue
            cs_base_url = data_loaded[client]['cs_base_url']
            cs_client_id = data_loaded[client]['cs_client_id']
            cs_client_secret = data_loaded[client]['cs_client_secret']
            cs_auth_token_file = data_loaded[client]['cs_auth_token_file']

            client_id = os.environ[cs_client_id]
            client_secret = os.environ[cs_client_secret]

            url = "{base_url}/oauth2/token".format(base_url=cs_base_url)

            payload = 'client_id={client_id}&client_secret={client_secret}'.format(
                client_id=client_id, client_secret=client_secret)
            headers = {
                'Accept': 'application/json',
                'Content-Type': 'application/x-www-form-urlencoded'
            }

            response = requests.request(
                "POST", url, headers=headers, data=payload)

            with open(cs_auth_token_file, 'w') as outfile:
                json.dump(response.json(), outfile)

    except yaml.YAMLError as exc:
        print(exc)
