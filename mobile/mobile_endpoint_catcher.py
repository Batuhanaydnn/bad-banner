import frida
import subprocess
import re
import sys

app_name = "yourappname"
# here you need to use the emulator name you will run. Since it is still under development, I will automate this part in the future, unfortunately you have to enter it for now. If you don't know what the emulator name is, you can use emulator --list-avds to see your available emulator names.
app_launch_command = "emulator -avd <emulator_name> -netdelay none -netspeed full -wipe-data -no-snapshot -no-boot-anim -no-audio -no-window -gpu off -wipe-data -skin 1080x1920 -no-accel"

apk_file = "path/to/your/file.apk"

# If you don't know what it is and won't use adb, you can find it by searching the internet a bit. Let me briefly explain how you can learn for adb here. You can find the serial number of your devices by typing adb devices.
device_serial = "your_device_serial_number"

endpoints = []

class MessageHandler:
    def on_message(self, message, data):
        if message['type'] == 'send':
            if 'endpoint' in message['payload']:
                endpoint = message['payload']['endpoint']
                endpoints.append(endpoint)

device = frida.get_usb_device()
pid = device.spawn([app_launch_command])
session = device.attach(pid)
device.resume(pid)


with open('script.js', 'r') as script_file:
    script_code = script_file.read()

script = session.create_script(script_code)
handler = MessageHandler()
script.on('message', handler.on_message)
script.load()

sys.stdin.read()

for endpoint in endpoints:
    print(endpoint)

def get_package_name(apk_file_path):
    command = f"aapt dump badging {apk_file_path} | grep package"
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    output = result.stdout.strip()
    package_name = output.split("'")[1]
    return package_name

install_command = f'adb -s {device_serial} install -r {apk_file}'
subprocess.run(install_command, shell=True)

package_name = get_package_name(apk_file)
start_command = f"adb -s {device_serial} shell monkey -p {package_name} -c android.intent.category.LAUNCHER 1"
subprocess.run(start_command, shell=True)

pull_command = f"adb -s {device_serial} install -r {apk_file}"
subprocess.run(install_command, shell=True)

source_file = f"{package_name}/base.apk"
with open(source_file, 'r') as file:
    source_code = file.read()

endpoints = re.findall(r"\"(http[s]?:://.*?\"", source_code)

for endpoint in endpoints:
    print(endpoint)


