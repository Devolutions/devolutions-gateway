#!/bin/bash

if command -v step-cli &> /dev/null; then
    step_cmd=step-cli
else
    if command -v step &> /dev/null; then
        step_cmd=step
    else
        echo "⚠ 'step-cli' not found. Please install it: https://github.com/smallstep/cli#installation"
        exit
    fi
fi

if [ "$#" -ne 8 ] && [ "$#" -ne 4 ]; then
    echo "Illegal number of parameters."
    echo "Usage: $0 <VALIDITY_DURATION_MINS> <PROVIDER_PRIVATE_KEY> <JET_PUBLIC_KEY> <DST_HST> [ <PRX_USR> <PRX_PWD> <DST_USR> <DST_PWD>" ]
    exit
fi

valid_for_mins="$1"
provider_key_path="$2"
jet_public_key_path="$3"
dst_hst="$4"

if [ "$#" -eq 8 ]; then
    prx_usr="$5"
    prx_pwd="$6"
    dst_usr="$7"
    dst_pwd="$8"

    claims="{
        \"jet_ap\": \"rdp\",
        \"jet_cm\": \"fwd\",
        \"dst_hst\": \"${dst_hst}\",
        \"prx_usr\": \"${prx_usr}\",
        \"prx_pwd\": \"${prx_pwd}\",
        \"dst_usr\": \"${dst_usr}\",
        \"dst_pwd\": \"${dst_pwd}\"
    }"
else
    claims="{
        \"jet_ap\": \"rdp\",
        \"jet_cm\": \"fwd\",
        \"dst_hst\": \"${dst_hst}\"
    }"
fi

printf "$claims" | ${step_cmd} crypto jwt sign - \
    -nbf $(date "+%s") \
    -exp $(date -d "$valid_for_mins minutes" "+%s") \
    -subtle \
    -key "$provider_key_path" \
    | tr -d '\n' \
    | ${step_cmd} crypto jwe encrypt \
    -alg RSA-OAEP-256 \
    -enc A256GCM \
    -key "$jet_public_key_path" \
    | ${step_cmd} crypto jose format

