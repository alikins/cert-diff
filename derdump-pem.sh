#!/bin/bash
#
# Adrian Likins <alikins@redhat.com> 2013
#  GPLv2
#
# Convert a PEM encoded x509 cert to DER and use 'derdump' to show the encoding details
#
# (or I guess, any x509 format that openssl x509 can read).
#
# from nsstools
DERDUMP="/usr/lib64/nss/unsupported-tools/derdump"
PEM_TO_DER="openssl x509 -outform DER -in"

IN_PEM=$1


DER_TO_DERDUMP="$DERDUMP -r"

# string it all together to dumpder a pem


$PEM_TO_DER $IN_PEM |  $DER_TO_DERDUMP
