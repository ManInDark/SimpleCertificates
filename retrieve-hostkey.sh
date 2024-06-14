#!/bin/sh
# $1: URL
curl "$1/retrieve?name=$(cat retrieval-key)" > /etc/ssh/host-key-cert.pub