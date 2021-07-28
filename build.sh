#!/bin/bash -xe

TAG=$(git describe --tags --always)
docker build . -t summittech/iptables-compose -t summittech/iptables-compose:$TAG
docker push summittech/iptables-compose:$TAG
docker push summittech/iptables-compose:latest