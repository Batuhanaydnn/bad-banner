#!/bin/bash

folder="YOUR_FOLDER_NAME.apk"
params=("api_key" "access_key" "firebase_key" "passwords" "password" "Runtime.exec()" "ProcessBuilder()" "native code:system()" "sendTextMessage" "sendMultipartTestMessage")


for param in "${params[@]}"; do
    echo "Aranıyor: $param"
    grep -rIl "$param" "$folder" 2>/dev/null
done