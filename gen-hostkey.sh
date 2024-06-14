#!/bin/sh
# $1: URL
ssh-keygen -f /etc/ssh/host-key -t rsa -b 4096 -N ""
echo HostKey /etc/ssh/host-key >> /etc/ssh/sshd_config
echo HostCertificate /etc/ssh/host-key-cert.pub >> /etc/ssh/sshd_config
curl -X POST --data-binary @/etc/ssh/host-key.pub $1 >> retrieval-key