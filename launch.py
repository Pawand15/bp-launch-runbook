launch_env = '@@{LAUNCH_ENV}@@'
bp_uuid = '@@{BP_UUID}@@'

pc_user = '@@{PC_CREDS.username}@@'
pc_pass = '@@{PC_CREDS.secret}@@'

vm_disks = '@@{VM_DISKS}@@'
server_role = '@@{SERVER_ROLE}@@'
os_name = '@@{OS}@@'

ram = @@{VM_RAM_MIB}@@
vcpu = @@{VM_VCPU}@@

os_images = '@@{OS_IMAGES}@@'

# set variables for testing
#launch_env = '{"cluster_uuid": "0005f90c-f979-edf8-0000-00000000bda1", "subnet_uuid": "0fc2dd68-b336-4dda-8ec2-add14a2e7f3c", "account": "699cd80b-75ee-4fd8-b86e-f4b6a1be9bee", "profile_name": "CORP_JPR", "profile_uuid": "cde26e8f-4a5a-42de-885e-55c16d070c3f"}'
#bp_uuid = '38505774-c463-4f18-86f7-94d436f8b919'

#pc_user = 'calmadmin'
#pc_pass = 'Nutanix@123'

#os_images = '{"WEB": {"WINDOWS_2019": {"IMAGES": {"0": {"image": "Win.*2019.*Web.*OS.*", "label": "OS"}, "1": {"image": "Win.*2019.*Web.*Agents.*", "label": "Agents"}}, "OS": "WINDOWS"}, "WINDOWS_2016": {"IMAGES": {"0": {"image": "Win.*2016.*Web.*OS.*", "label": "OS"}, "1": {"image": "Win.*2016.*Web.*Agents.*", "label": "Agents"}}, "OS": "WINDOWS"}, "RHEL_7": {"IMAGES": {"0": {"image": "CentOS.*OS.*Web.*"}, "1": {"image": "CentOS.*Agents.*", "lvm_addr": "/dev/vg_sdb/lv_agents", "mount_point": "/agents"}}, "OS": "LINUX"}}, "APP": {"WINDOWS_2019": {"IMAGES": {"0": {"image": "Win.*2019.*App.*OS.*", "label": "OS"}, "1": {"image": "Win.*2019.*App.*Agents.*", "label": "Agents"}}, "OS": "WINDOWS"}, "WINDOWS_2016": {"IMAGES": {"0": {"image": "Win.*2016.*App.*OS.*", "label": "OS"}, "1": {"image": "Win.*2016.*App.*Agents.*", "label": "Agents"}}, "OS": "WINDOWS"}, "RHEL_7": {"IMAGES": {"0": {"image": "CentOS.*OS.*"}, "1": {"image": "CentOS.*Agents.*", "lvm_addr": "/dev/vg_sdb/lv_agents", "mount_point": "/agents"}}, "OS": "LINUX"}}, "DB": {"WINDOWS_2019": {"IMAGES": {"0": {"image": "Win.*2019.*DB.*OS.*", "label": "OS"}, "1": {"image": "Win.*2019.*DB.*Agents.*", "label": "Agents"}}, "OS": "WINDOWS"}, "WINDOWS_2016": {"IMAGES": {"0": {"image": "Win.*2016.*DB.*OS.*", "label": "OS"}, "1": {"image": "Win.*2016.*DB.*Agents.*", "label": "Agents"}}, "OS": "WINDOWS"}, "RHEL_7": {"IMAGES": {"0": {"image": "CentOS.*OS.*"}, "1": {"image": "CentOS.*Agents.*", "lvm_addr": "/dev/vg_sdb/lv_agents", "mount_point": "/agents"}}, "OS": "LINUX"}}}'

#vm_disks = '/backup:10240'
#server_role = 'WEB'
#os_name = 'RHEL_7'

#ram = 4096
#vcpu = 1

# convert json strings from prv tasks to dict
os_images = json.loads(os_images)
launch_env = json.loads(launch_env)

headers = {'Content-Type': 'application/json'}

#get runtime editables for blueprint
api_url = 'https://localhost:9440/api/nutanix/v3/blueprints/{}/runtime_editables'.format(bp_uuid)
r = urlreq(api_url, verb='GET', auth='BASIC', user=pc_user, passwd=pc_pass, headers=headers, verify=False)
resp = json.loads(r.content)

for resource in resp['resources']:
    if resource['app_profile_reference']['name'] == launch_env['profile_name']:
        editables = resource['runtime_editables']

editables['credential_list'][0]['value']['secret']['attrs']['is_secret_modified'] = True
editables['credential_list'][0]['value']['secret']['value'] = '@@{VM_PASSWORD}@@'

editables['substrate_list'][0]['value']['spec']['cluster_reference']['uuid'] = launch_env['cluster_uuid']
del editables['substrate_list'][0]['value']['spec']['cluster_reference']['name']

editables['substrate_list'][0]['value']['spec']['resources']['nic_list']['0']['subnet_reference']['uuid'] = launch_env['subnet_uuid']
del editables['substrate_list'][0]['value']['spec']['resources']['nic_list']['0']['subnet_reference']['name']
del editables['substrate_list'][0]['value']['spec']['resources']['nic_list']['0']['vpc_reference']

editables['substrate_list'][0]['value']['spec']['resources']['num_vcpus_per_socket'] = vcpu
editables['substrate_list'][0]['value']['spec']['resources']['memory_size_mib'] = ram

#windows sysprep configuration
if os_images[server_role][os_name]['OS'].upper() == 'WINDOWS':
    
    # sysprep template for windows
    sys_prep_pre = '''<?xml version="1.0" encoding="UTF-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
   <settings pass="specialize">
      <component xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
         <ComputerName>@@{VM_NAME}@@</ComputerName>
         <RegisteredOrganization>Nutanix</RegisteredOrganization>
         <RegisteredOwner>Acropolis</RegisteredOwner>
         <TimeZone>Pacific Standard Time</TimeZone>
      </component>
      <component xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" name="Microsoft-Windows-TCPIP" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
         <Interfaces>
            <Interface wcm:action="add">
               <Identifier>Ethernet</Identifier>
               <Ipv4Settings>
                  <DhcpEnabled>false</DhcpEnabled>
                  <RouterDiscoveryEnabled>true</RouterDiscoveryEnabled>
                  <Metric>30</Metric>
               </Ipv4Settings>
               <UnicastIpAddresses>
                  <IpAddress wcm:action="add" wcm:keyValue="1">@@{VM_IP}@@@@{SUBNET_PREFIX}@@</IpAddress>
               </UnicastIpAddresses>
               <Routes>
                  <Route wcm:action="add">
                     <Identifier>10</Identifier>
                     <Metric>20</Metric>
                     <NextHopAddress>@@{GATEWAY_IP}@@</NextHopAddress>
                     <Prefix>0.0.0.0/0</Prefix>
                  </Route>
               </Routes>
            </Interface>
         </Interfaces>
      </component>
      <component xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" name="Microsoft-Windows-DNS-Client" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
         <UseDomainNameDevolution>true</UseDomainNameDevolution>
         <DNSDomain>ntnxlab.local</DNSDomain>
         <Interfaces>
            <Interface wcm:action="add">
               <Identifier>Ethernet</Identifier>
               <DNSDomain>ntnxlab.local</DNSDomain>
               <DNSServerSearchOrder>
                  <IpAddress wcm:action="add" wcm:keyValue="1">@@{PRIMARY_DNS}@@</IpAddress>
                  <IpAddress wcm:action="add" wcm:keyValue="2">@@{SECONDARY_DNS}@@</IpAddress>
               </DNSServerSearchOrder>
               <EnableAdapterDomainNameRegistration>true</EnableAdapterDomainNameRegistration>
               <DisableDynamicUpdate>true</DisableDynamicUpdate>
            </Interface>
         </Interfaces>
      </component>
      <component xmlns="" name="Microsoft-Windows-TerminalServices-LocalSessionManager" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" processorArchitecture="amd64">
         <fDenyTSConnections>false</fDenyTSConnections>
      </component>
      <component xmlns="" name="Microsoft-Windows-TerminalServices-RDP-WinStationExtensions" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" processorArchitecture="amd64">
         <UserAuthentication>0</UserAuthentication>
      </component>
      <component xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" name="Networking-MPSSVC-Svc" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
         <FirewallGroups>
            <FirewallGroup wcm:action="add" wcm:keyValue="RemoteDesktop">
               <Active>true</Active>
               <Profile>all</Profile>
               <Group>@FirewallAPI.dll,-28752</Group>
            </FirewallGroup>
         </FirewallGroups>
      </component>
   </settings>
   <settings pass="oobeSystem">
      <component xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
         <UserAccounts>
            <AdministratorPassword>
               <Value>@@{VM_PASSWORD}@@</Value>
               <PlainText>true</PlainText>
            </AdministratorPassword>
         </UserAccounts>
         <AutoLogon>
            <Password>
               <Value>@@{VM_PASSWORD}@@</Value>
               <PlainText>true</PlainText>
            </Password>
            <Enabled>true</Enabled>
            <Username>administrator</Username>
         </AutoLogon>
         <FirstLogonCommands>            
'''

    xml_command_block = '''            <SynchronousCommand wcm:action="add">
               <CommandLine>powershell -Command "##command##"</CommandLine>
               <Description>##description##</Description>
               <Order>##order##</Order>
               <RequiresUserInput>false</RequiresUserInput>
            </SynchronousCommand>
'''

    sys_prep_post = '''         </FirstLogonCommands>
         <OOBE>
            <HideEULAPage>true</HideEULAPage>
            <SkipMachineOOBE>true</SkipMachineOOBE>
         </OOBE>
      </component>
      <component xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" name="Microsoft-Windows-International-Core" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
         <InputLocale>en-US</InputLocale>
         <SystemLocale>en-US</SystemLocale>
         <UILanguageFallback>en-us</UILanguageFallback>
         <UILanguage>en-US</UILanguage>
         <UserLocale>en-US</UserLocale>
      </component>
   </settings>
</unattend>'''

    order = 1
    drive_letters = 'CEFGHIJKLMNOPQRSTUVWXYZ'
  
    if len('@@{VM_NAME}@@') > 14:
        sys_prep_pre = sys_prep_pre.replace('@@{VM_NAME}@@','@@{VM_NAME}@@'[0:15])
  
    sys_prep_commands = ''
    
    #initiazlize, rename disks created from images
    for disk_num, disk_details in os_images[server_role][os_name]['IMAGES'].items():
        if int(disk_num) > 0:
            sys_prep_commands += xml_command_block.replace('##order##', str(order)).replace('##description##', 'Initialize Disk {}'.format(disk_details['label'])).replace('##command##', 'Get-Disk -Number {0} | Initialize-Disk -ErrorAction SilentlyContinue'.format(disk_num))
            order += 1        
        sys_prep_commands += xml_command_block.replace('##order##', str(order)).replace('##description##', 'Rename Disk {}'.format(disk_details['label'])).replace('##command##', 'Set-Volume -DriveLetter {0} -NewFileSystemLabel "{1}"'.format(drive_letters[int(disk_num)], disk_details['label']))
        order += 1 
    
    #initiazlize, create partion, format empty disks
    if vm_disks.strip():
        for disk_num, disk in enumerate(vm_disks.split(','), start=len(os_images[server_role][os_name]['IMAGES'].values())):
            sys_prep_commands += xml_command_block.replace('##order##', str(order)).replace('##description##', 'Initialize Disk {}'.format(disk.split(':')[0])).replace('##command##', 'Get-Disk -Number {0} | Initialize-Disk -ErrorAction SilentlyContinue'.format(str(disk_num)))
            order += 1 
            sys_prep_commands += xml_command_block.replace('##order##', str(order)).replace('##description##', 'Create Partition For Disk {}'.format(disk.split(':')[0])).replace('##command##', 'New-Partition -DiskNumber {0} -DriveLetter {1} -UseMaximumSize -ErrorAction SilentlyContinue'.format(str(disk_num), drive_letters[disk_num]))
            order += 1
            sys_prep_commands += xml_command_block.replace('##order##', str(order)).replace('##description##', 'Format Disk {}'.format(disk.split(':')[0])).replace('##command##', "Format-Volume -DriveLetter {0} -FileSystem NTFS -NewFileSystemLabel '{1}' -Confirm:$false".format(drive_letters[disk_num], disk.split(':')[0]))
            order += 1           
    
    editables['substrate_list'][0]['value']['spec']['resources']['guest_customization']['sysprep']['unattend_xml'] = sys_prep_pre + sys_prep_commands + sys_prep_post
    #print editables['substrate_list'][0]['value']['spec']['resources']['guest_customization']['sysprep']['unattend_xml']
    
#linux cloud init
else:
    cloud_init_pre = '''#cloud-config
chpasswd:
  list: |
     root:@@{VM_PASSWORD}@@
  expire: False
fqdn: "@@{VM_NAME}@@"
ssh_pwauth: True
runcmd: 
  - "nmcli con mod 'System {0}' ipv4.addresses @@{VM_IP}@@@@{SUBNET_PREFIX}@@"
  - "nmcli con mod 'System {0}' ipv4.gateway @@{GATEWAY_IP}@@"'''.format('eth0') #ens3 - icici
    
    cloud_init_command_block = '''
  - "##command##"'''
    
    cloud_init_post = '''
  - "mount -a"  
  - "nmcli con mod 'System {0}' ipv4.method manual"
  - "nmcli con up 'System {0}'"
  - "touch /etc/cloud/cloud-init.disabled"'''.format('eth0') #ens3 - icici
    
    cloud_init_commands = ''
    
    if '@@{PRIMARY_DNS}@@'.strip():
        cloud_init_commands += cloud_init_command_block.replace('##command##', "nmcli con mod 'System {0}' ipv4.dns '@@{PRIMARY_DNS}@@ @@{SECONDARY_DNS}@@ @@{TERTIARY_DNS}@@'".format('eth0')) #ens3 - icici
    
    #create pv, vg, lv, format, mount empty disks
    disk_letters = 'abcdefghijklmnopqrstuvwxyz'
    
    #mount additional disk images
    #uncomment below in case mount points to be created, fstab entries need to be added
    #for disk_num, disk_details in os_images[server_role][os_name]['IMAGES'].items():
        #if int(disk_num) > 0:
            #mount_point = disk_details['mount_point']
            #lvm_addr = disk_details['lvm_addr']            
            #cloud_init_commands += cloud_init_command_block.replace('##command##', 'mkdir -p {}'.format(mount_point))
            #cloud_init_commands += cloud_init_command_block.replace('##command##', "echo '{} {}  xfs  defaults 0 0' | tee -a /etc/fstab".format(lvm_addr, mount_point))    
    
    #configure empty disks
    if vm_disks.strip():
        for disk_num, disk in enumerate(vm_disks.split(','), start=len(os_images[server_role][os_name]['IMAGES'].values())):
            mount_point = disk.split(':')[0]
            disk_name = '/dev/sd{}'.format(disk_letters[disk_num])
            vg_name = 'vg_sd{}'.format(disk_letters[disk_num])
            lv_name = 'lv_{}'.format(mount_point[mount_point.rfind('/') + 1:])
            cloud_init_commands += cloud_init_command_block.replace('##command##', 'pvcreate {}'.format(disk_name))
            cloud_init_commands += cloud_init_command_block.replace('##command##', 'vgcreate {} {}'.format(vg_name, disk_name))
            cloud_init_commands += cloud_init_command_block.replace('##command##', 'lvcreate -l +100%FREE -n {} {}'.format(lv_name, vg_name))
            cloud_init_commands += cloud_init_command_block.replace('##command##', 'mkfs.xfs /dev/{}/{}'.format(vg_name, lv_name))
            cloud_init_commands += cloud_init_command_block.replace('##command##', 'mkdir -p {}'.format(mount_point))
            cloud_init_commands += cloud_init_command_block.replace('##command##', "echo '/dev/{}/{} {}  xfs  defaults 0 0' | tee -a /etc/fstab".format(vg_name, lv_name, mount_point))
          

    editables['substrate_list'][0]['value']['spec']['resources']['guest_customization']['cloud_init']['user_data'] = cloud_init_pre + cloud_init_commands + cloud_init_post
    #print editables['substrate_list'][0]['value']['spec']['resources']['guest_customization']['cloud_init']['user_data']

#set images
api_url = 'https://localhost:9440/api/nutanix/v3/nutanix/v1/images/list'

device_index = 0

#add images based on search string
for disk_id in range(0, len(os_images[server_role][os_name]['IMAGES'].keys())):
    image_regex = os_images[server_role][os_name]['IMAGES'][str(disk_id)]['image']   
    payload = {
        "length": 1000,
        "offset": 0,
        "filter":'account_uuid=={0};name=={1}'.format(launch_env['account'], image_regex)
    }
    r = urlreq(api_url, verb='POST', auth='BASIC', user=pc_user, passwd=pc_pass, params=json.dumps(payload), headers=headers, verify=False)
    resp = json.loads(r.content)
    #print json.dumps(resp)
    if disk_id == '0':
        editables['substrate_list'][0]['value']['spec']['resources']['disk_list'][str(device_index)]['data_source_reference']['name'] = resp['entities'][0]['spec']['name']
        editables['substrate_list'][0]['value']['spec']['resources']['disk_list'][str(device_index)]['data_source_reference']['uuid'] = resp['entities'][0]['metadata']['uuid']
    else:     
        editables['substrate_list'][0]['value']['spec']['resources']['disk_list'][str(device_index)] = {
            'data_source_reference': {
                'kind': 'image',
                'name': resp['entities'][0]['spec']['name'],
                'uuid': resp['entities'][0]['metadata']['uuid']
            },
            "device_properties": {
                "device_type": "DISK",
                "disk_address": {
                    "adapter_type": "SCSI",
                    "device_index": device_index
                }
            }
        }
    device_index += 1    

# add empty disks    
if vm_disks.strip():
    for disk in vm_disks.split(','):
        editables['substrate_list'][0]['value']['spec']['resources']['disk_list'][device_index] = {
            "data_source_reference": None,
            "device_properties": {
                "device_type": "DISK",
                "disk_address": {
                    "adapter_type": "SCSI",
                    "device_index": device_index
                }
            },
            "disk_size_mib": disk.split(':')[1]
        }
        device_index += 1

api_url = 'https://localhost:9440/api/nutanix/v3/blueprints/{}/simple_launch'.format(bp_uuid)
payload = {
  'spec': {
    'app_profile_reference': {
      'kind': 'app_profile',
      'name': launch_env['profile_name'],
      'uuid': launch_env['profile_uuid'],
    },
    'app_name': '@@{VM_NAME}@@',
    'runtime_editables': editables
  }
}

#print json.dumps(payload)

r = urlreq(api_url, verb='POST', auth='BASIC', user=pc_user, passwd=pc_pass, params=json.dumps(payload), headers=headers, verify=False)
resp = json.loads(r.content)
print resp
