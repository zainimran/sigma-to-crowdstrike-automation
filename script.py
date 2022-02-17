import yaml
import requests
import json
import sys

# parse a sigma rule in a yaml file and get its contents
with open(sys.argv[1], 'r') as stream:
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

exclude_ident = None
if 'filter' in detection:
    exclude_ident = 'filter'
elif 'browser_process' in detection:
    exclude_ident = 'browser_process'

if exclude_ident is not None:
    image_values = []
    if 'Image|contains' in detection[exclude_ident]:
        image_list = detection[exclude_ident]['Image|contains']
        for image in image_list:
            image = ".*{image}.*".format(image=image)
            image_values.append({
                "label": "exclude",
                "value": image
            })
    elif 'Image|endswith' in detection[exclude_ident]:
        image_list = detection[exclude_ident]['Image|endswith']
        for image in image_list:
            image = image.replace('\\', '')
            # image = image.replace('.', '\.', 1)
            image = ".*{image}".format(image=image)
            image_values.append({
                "label": "exclude",
                "value": image
            })
    if len(image_values) == 0:
        image_values = ''
    field_values.append({
        "name": "ImageFilename",
        "label": "Image Filename",
        "type": "excludable",
        "values": image_values
    })

if 'dns_request' in detection:
    dns_values = []
    if 'QueryName' in detection['dns_request']:
        dns_list = detection['dns_request']['QueryName']
        for dns in dns_list:
            # dns = dns.replace('.', '\.')
            dns_values.append({
                "label": "include",
                "value": dns
            })
    elif 'QueryName|contains' in detection['dns_request']:
        dns_list = detection['dns_request']['QueryName|contains']
        for dns in dns_list:
            # dns = dns.replace('.', '\.')
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

with open('config.yml', 'r') as stream:
    try:
        data_loaded = yaml.safe_load(stream)
        client_list = list(data_loaded.keys())
        for client in client_list:
            if 'cs_base_url' not in data_loaded[client]:
                continue
            cs_base_url = data_loaded[client]['cs_base_url']
            rule_creation_user = data_loaded[client]['rule_creation_user']
            rulegroup_id = data_loaded[client]['rulegroup_id']
            cs_disposition_id = data_loaded[client]['cs_disposition_id']
            cs_auth_token_file = data_loaded[client]['cs_auth_token_file']

            url = "{base_url}/ioarules/entities/rules/v1".format(base_url=cs_base_url)
            payload = json.dumps({
                "name": name,
                "comment": description,
                "description": description,
                "pattern_severity": pattern_severity,
                "rulegroup_id": rulegroup_id,
                "ruletype_id": ruletype_id,
                "disposition_id": cs_disposition_id,
                "field_values": field_values
            }, indent=4, sort_keys=True)

            print(payload)

            # load a json file and read its content
            with open(cs_auth_token_file, 'r') as data_file:
                data = json.load(data_file)
                auth_token = data['access_token']

            headers = {
                'X-CS-USERNAME': rule_creation_user,
                'Authorization': 'Bearer {token}'.format(token=auth_token),
                'Content-Type': 'application/json'
            }
            response = requests.request("POST", url, headers=headers, data=payload)

            print(response.text)
    except yaml.YAMLError as exc:
        print(exc)