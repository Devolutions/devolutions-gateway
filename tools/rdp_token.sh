#!/bin/bash

if [ "$#" -ne 8 ]; then
    echo "Illegal number of parameters."
    echo "Usage: $0 <VALIDITY_DURATION_MINS> \
<PROVIDER_PRIVATE_KEY> <JET_PUBLIC_KEY> \
<PRX_USR> <PRX_PWD> \
<DST_USR> <DST_PWD> <DST_HST>"
    exit
fi

valid_for_mins="$1"
provider_key_path="$2"
jet_public_key_path="$3"
prx_usr="$4"
prx_pwd="$5"
dst_usr="$6"
dst_pwd="$7"
dst_hst="$8"

claims="{
    \"jet_ap\": \"rdp\",
    \"jet_cm\": \"fwd\",
    \"dst_hst\": \"${dst_hst}\"
}"

echo "$claims" | step-cli crypto jwt sign - \
    -nbf $(date "+%s") \
    -exp $(date -d "$valid_for_mins minutes" "+%s") \
    -subtle \
    -key "$provider_key_path" \
    | step-cli crypto jwe encrypt \
    -alg RSA-OAEP-256 \
    -enc A256GCM \
    -key "$jet_public_key_path" \
    | step-cli crypto jose format
