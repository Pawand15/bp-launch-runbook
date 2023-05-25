bp_uuid = '@@{BP_UUID}@@'

selected_cluster = '@@{CLUSTER_NAME}@@'
selected_subnet = '@@{VLAN_ID}@@'

pc_user = '@@{PC_CREDS.username}@@'
pc_pass = '@@{PC_CREDS.secret}@@'

dns_details = '@@{DNS_DETAILS}@@'

#set variable values for testing
#bp_uuid = '38505774-c463-4f18-86f7-94d436f8b919'

#selected_cluster = 'PHX-POC320'
#selected_subnet = '0'

#pc_user = 'calmadmin'
#pc_pass = 'Nutanix@123'

#dns_details = '{"DMZ_JPR": {"PRIMARY_DNS": "1.1.1.1", "TERTIARY_DNS": "8.8.4.4", "SECONDARY_DNS": "8.8.8.8"}, "CORP_HYD_1": {"PRIMARY_DNS": "8.8.8.8", "TERTIARY_DNS": "8.8.4.4", "SECONDARY_DNS": "1.1.1.1"}, "CORP_JPR": {"PRIMARY_DNS": "1.1.1.1", "TERTIARY_DNS": "8.8.4.4", "SECONDARY_DNS": "8.8.8.8"}, "CORP_HYD_2": {"PRIMARY_DNS": "8.8.8.8", "TERTIARY_DNS": "8.8.4.4", "SECONDARY_DNS": "1.1.1.1"}}'

# convert json string from prv tasks to dict
dns_details = json.loads(dns_details)

headers = {'Content-Type': 'application/json'}

api_url = 'https://localhost:9440/api/nutanix/v3/blueprints/{}'.format(bp_uuid)
r = urlreq(api_url, verb='GET', auth='BASIC', user=pc_user, passwd=pc_pass, headers=headers, verify=False)
resp = json.loads(r.content)

#print json.dumps(resp)

app_profiles = []

# get list of app profiles mapped to various PCs
for app_profile in resp['spec']['resources']['app_profile_list']:    
    for substrate in resp['spec']['resources']['substrate_definition_list']:
        if substrate['uuid'] == app_profile['deployment_create_list'][0]['substrate_local_reference']['uuid']:            
            app_profiles.append({
                'profile_name': app_profile['name'],
                'profile_uuid': app_profile['uuid'],
                'acc_uuid': substrate['create_spec']['resources']['account_uuid']
            })
            break
            
    #print app_profile['name'], app_profile['uuid'], substrate['create_spec']['resources']['account_uuid']

api_url = 'https://localhost:9440/api/nutanix/v3/accounts/list'
payload = {}
r = urlreq(api_url, verb='POST', auth='BASIC', user=pc_user, passwd=pc_pass, params=json.dumps(payload), headers=headers, verify=False)
resp = json.loads(r.content)

#print json.dumps(resp)

launch_env = {}

#get cluster uuid and corresponding pc account uuid from the cluster name
for entity in resp['entities']:
    if entity['metadata']['name'].replace('_','-') == selected_cluster.replace('_','-'):
        launch_env['cluster_uuid'] = entity['status']['resources']['data']['cluster_uuid']
        launch_env['account'] = entity['status']['resources']['data']['pc_account_uuid']
        break

#get profile based on pc account uuid  
for entity in resp['entities']:
    if entity['metadata']['uuid'] == launch_env['account']:
        for cluster in entity['status']['resources']['data']['cluster_account_reference_list']:
            for app_profile in app_profiles:
                if app_profile['acc_uuid'] == cluster['uuid']:
                    launch_env['profile_name'] = app_profile['profile_name']
                    launch_env['profile_uuid'] = app_profile['profile_uuid']
                    break
        break

api_url = 'https://localhost:9440/api/nutanix/v3/nutanix/v1/subnets/list'

#get subnet uuid based on cluster and vlan id
payload = {
        'filter': 'account_uuid=={0};vlan_id=={1}'.format(launch_env['account'], selected_subnet)
}
r = urlreq(api_url, verb='POST', auth='BASIC', user=pc_user, passwd=pc_pass, params=json.dumps(payload), headers=headers, verify=False)
resp = json.loads(r.content)
for entity in resp['entities']:
    if entity['status']['cluster_reference']['uuid'] == launch_env['cluster_uuid']:            
        launch_env['subnet_uuid'] = entity['metadata']['uuid']            
        break

print 'LAUNCH_ENV={}'.format(json.dumps(launch_env))

#get dns based on profile
if 'DMZ' not in selected_cluster.upper():  
    print 'PRIMARY_DNS={}'.format(dns_details[launch_env['profile_name']]['PRIMARY_DNS'])
    print 'SECONDARY_DNS={}'.format(dns_details[launch_env['profile_name']]['SECONDARY_DNS'])
    print 'TERTIARY_DNS={}'.format(dns_details[launch_env['profile_name']]['TERTIARY_DNS'])
else:
    print 'PRIMARY_DNS='
    print 'SECONDARY_DNS='
    print 'TERTIARY_DNS='
