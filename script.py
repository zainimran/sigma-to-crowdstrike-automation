import yaml
import requests
import json
import sys

# parse a sigma rule in a yaml file and get its contents
with open('rules\dns\dns_net_susp_ipify.yml', 'r') as stream:
    try:
        data_loaded = yaml.safe_load(stream)
        name = data_loaded['title']
        description = data_loaded['description']
        pattern_severity = data_loaded['level']
        product = data_loaded['logsource']['product']
        category = data_loaded['logsource']['category']
        detection = data_loaded['detection']
    except yaml.YAMLError as exc:
        print(exc)

ruletype_id = "0"
if product == 'windows':
    if category == 'dns_query':
        ruletype_id = "11"
    elif category == 'process_creation':
        ruletype_id = '5'

field_values = []

search_ident = detection.get('filter') or detection.get('browser_process')
if search_ident:
    image_filter = ''
    if 'Image|contains' in detection[search_ident]:
        image_filter = ".*{detection}.*".format(
            detection=detection[search_ident]['Image|contains'])
        field_values.append({
            "name": "ImageFilename",
            "label": "Image Filename",
            "type": "excludable",
            "values": [{
                "label": "exclude",
                "value": image_filter
            }
            ]
        })
    elif 'Image|endswith' in detection[search_ident]:
        image_filter = ".*{detection}".format(
            detection=detection[search_ident]['Image|endswith'].replace(
                '\\', '', 1))
        field_values.append({
            "name": "ImageFilename",
            "label": "Image Filename",
            "type": "excludable",
            "values": [{
                "label": "exclude",
                "value": image_filter
            }
            ]
        })

if 'dns_request' in detection:
    dns_values = []
    if 'QueryName' in detection['dns_request']:
        dns_list = detection['dns_request']['QueryName']
        for dns in dns_list:
            dns_values.append({
                "label": "include",
                "value": dns
            })
    elif 'QueryName|contains' in detection['dns_request']:
        dns_list = detection['dns_request']['QueryName|contains']
        for dns in dns_list:
            dns = ".*{detection}.*".format(
                detection=detection['dns_request']['QueryName|contains'])
            dns_values.append({
                "label": "include",
                "value": dns
            })
    if len(dns_values) == 0:
        dns_values = ".*"
    field_values.append({
        "name": "DomainName",
        "label": "Domain Name",
        "type": "excludable",
        "values": dns_values
    })

payload = json.dumps({
    "name": name,
    "comment": description,
    "description": description,
    "pattern_severity": pattern_severity,
    "rulegroup_id": "cd2f65a62b7241478ca9a2f9aded6c63",
    "ruletype_id": ruletype_id,
    "disposition_id": 10,
    "field_values": field_values
}, indent=4, sort_keys=True)

headers = {
    'X-CS-USERNAME': 'zain.imran@ebryx.com',
    'Authorization': 'Bearer {token}'.format(token=sys.argv[2]),
    'Content-Type': 'application/json'
}

url = "https://api.us-2.crowdstrike.com/ioarules/entities/rules/v1"

response = requests.request("POST", url, headers=headers, data=payload)

print(response.text)
