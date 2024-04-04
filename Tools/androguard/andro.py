import os
from androguard.core.bytecodes.apk import APK

filename = os.getenv("Filename")
apk_file_path = '/app/data/'+filename
a = APK(apk_file_path)

sign = {}
sign['activities'] = a.get_activities()
sign['features'] = a.get_features()
sign['libraries'] = a.get_libraries()
sign['main_activity'] = a.get_main_activity()
sign['min_sdk_version'] = a.get_min_sdk_version()
sign['max_sdk_version'] = a.get_max_sdk_version()
sign['target_sdk_version'] = a.get_target_sdk_version()
sign['permissions'] = a.get_permissions()
sign['aosp_permissions'] = a.get_requested_aosp_permissions()
sign['third_party_permissions'] = a.get_requested_third_party_permissions()
sign['providers'] = a.get_providers()
sign['receivers'] = a.get_receivers()
sign['services'] = a.get_services()

print(sign)
