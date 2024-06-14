#!/bin/sh
# $1: Username
# $2: Password
# $3: URL
# $4: retrieval key
# $5: Identity to sign for
# $6: if set is signed as server certificate
curl "$1:$2@$3/sign?name=$4&identity=$5&server=$6"