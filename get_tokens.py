import yaml
import requests
import json
import sys
import os

print(os.environ['SECRETS'])


# with open('config.yml', 'r') as stream:
#     try:
#         data_loaded = yaml.safe_load(stream)
#         cs_base_url = data_loaded['cs_base_url']
#     except yaml.YAMLError as exc:
#         print(exc)


# url = "{base_url}/oauth2/token".format(base_url=cs_base_url)

# payload='client_id=c0f5df9a9efb4c7b8c96f9737652b780&client_secret=Xr5fkwR3yLCSKJ7PB24Etos0QMb98lDWz61aAdVZXr5fkwR3yLCSKJ7PB24Etos0QMb98lDWz61aAdVZ'
# headers = {
#   'Accept': 'application/json',
#   'Content-Type': 'application/x-www-form-urlencoded'
# }

# response = requests.request("POST", url, headers=headers, data=payload)

# print(response.text)
