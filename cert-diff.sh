#!/bin/bash
#
# Adrian Likins <alikins@redhat.com>
#
# GPL v2 
#
# cert-diff cert1.pem cert2.pem

FILE1="${1}"
FILE2="${2}"

# FIXME: should be no need for temp files, but git diff doesnt seem to like process sub

DIFF_OPTIONS="--minimal --histogram"
GIT_WORD_DIFF="git --no-pager diff --color-words --no-index ${DIFF_OPTIONS}"
GIT_DIFF="git --no-pager diff --no-index ${DIFF_OPTIONS}"
GNU_DIFF="diff -d -u"
DIFF="${GIT_DIFF}"
PP="/usr/lib64/nss/unsupported-tools/pp"
DERDUMP="/usr/lib64/nss/unsupported-tools/derdump"
DUMPDER="openssl x509 -outform DER -in"


# use 'git diff' even though it's not in git, for color.
gen_diff() {
    ${GIT_DIFF} "${1}" "${2}"
    ${GIT_WORD_DIFF} "${1}" "${2}"
}
# comparisons
#   openssl x509 -text -in
#   /usr/lib64/nss/unsupported-tools/pp -t
#   openssl asn1parse -in /etc/pki/consumer/cert.pem -inform PEM -i
#   openssl x509 -outform DER -i $INFILE | /usr/lib64/nss/unsupported-tools/derdump -r

#FIXME: should split pem file bundles into multiple files

# use textout options to cleanup diff?
FILE1_TXT="${FILE1}".txt
openssl x509 -text -in "${FILE1}" > "${FILE1_TXT}"

FILE2_TXT="${FILE2}".txt
openssl x509 -text -in "${FILE2}" > "${FILE2_TXT}"

echo
echo "openssl x509 -text output"
gen_diff "${FILE1_TXT}" "${FILE2_TXT}"

FILE1_PP="${FILE1}.pp"
FILE1_DER="${FILE1}.der"
${DUMPDER} "${FILE1}" > "${FILE1_DER}"
${PP} -t certificate -i "${FILE1_DER}" > "${FILE1_PP}"


FILE2_PP="${FILE2}.pp"
FILE2_DER="${FILE2}.der"
${DUMPDER} "${FILE2}" > "${FILE2_DER}"
${PP} -t certificate -i "${FILE2_DER}" > "${FILE2_PP}"

echo
echo "pp -t certificate output"
gen_diff "${FILE1_PP}" "${FILE2_PP}"


FILE1_ASN1="${FILE1}.asn1"
openssl asn1parse -in "${FILE1}" -inform PEM -i > "${FILE1_ASN1}"

FILE2_ASN1="${FILE2}.asn1"
openssl asn1parse -in "${FILE2}" -inform PEM -i > "${FILE2_ASN1}"

echo
echo "openssl ans1parse output"
gen_diff "${FILE1_ASN1}" "${FILE2_ASN1}"

FILE1_DERDUMP="${FILE1}.derdump"
FILE2_DERDUMP="${FILE2}.derdump"

${DERDUMP} -r < "${FILE1_DER}" > "${FILE1_DERDUMP}"
${DERDUMP} -r < "${FILE2_DER}" > "${FILE2_DERDUMP}"

echo
echo "derdump output"
gen_diff "${FILE1_DERDUMP}" "${FILE2_DERDUMP}"

