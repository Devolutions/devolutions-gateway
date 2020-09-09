#!/bin/bash

if [ "$#" -ne 4 ]; then
    echo "Illegal number of parameters."
    echo "Usage: $0 <TARGET_HOST> <VALIDITY_DURATION_MINS> <PROVIDER_PRIVATE_KEY> <JET_PUBLIC_KEY>"
    exit
fi

target_host="$1"
valid_for_mins="$2"
provider_key_path="$3"
jet_public_key_path="$4"

claims="{
    \"dst_hst\": \"${target_host}\",
    \"jet_ap\": \"rdp\",
    \"jet_cm\": \"fwd\"
}"

echo "$claims" | step-cli crypto jwt sign - \
    -nbf $(date "+%s") \
    -exp $(date -d "$valid_for_mins minutes" "+%s") \
    -subtle \
    -key "$provider_key_path" \
    | step-cli crypto jwe encrypt \
    -alg RSA-OAEP-256 \
    -enc A256GCM \
    -key "$jet_public_key_path"
