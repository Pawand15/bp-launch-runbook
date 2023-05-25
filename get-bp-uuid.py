os_images = '@@{OS_IMAGES}@@'
server_role = '@@{SERVER_ROLE}@@'
os_name = '@@{OS}@@'

os_images = json.loads(os_images)

if os_images[server_role][os_name]['OS'].upper() == 'WINDOWS':
  print('Use Windows Blueprint')
  print 'BP_UUID=@@{WINDOWS_BP_UUID}@@'
else:  
  print('Use Linux Blueprint')
  print 'BP_UUID=@@{LINUX_BP_UUID}@@'
