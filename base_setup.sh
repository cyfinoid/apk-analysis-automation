#!/bin/bash
git clone https://github.com/rednaga/APKiD
cd APKiD
docker build . -t rednaga:apkid
cd ..
rm -rf APKiD

git clone https://github.com/quark-engine/quark-engine.git
cd quark-engine/
docker build . -t quark
cd ..
rm -rf quark-engine

docker pull docker.elastic.co/elasticsearch/elasticsearch:8.8.0

docker pull opensecurity/mobile-security-framework-mobsf

docker pull exodusprivacy/exodus-standalone

go mod download

#install redis
# curl -fsSL https://packages.redis.io/gpg | sudo gpg --dearmor -o /usr/share/keyrings/redis-archive-keyring.gpg
# echo "deb [signed-by=/usr/share/keyrings/redis-archive-keyring.gpg] https://packages.redis.io/deb $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/redis.list
# sudo apt-get update
# sudo apt-get install redis

