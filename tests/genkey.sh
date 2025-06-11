#!/bin/bash
PRIVATE_KEY=$(wg genkey)
PUBLIC_KEY=$(echo "$PRIVATE_KEY" | wg pubkey)

echo "Private Key: $PRIVATE_KEY"
echo "Public Key:  $PUBLIC_KEY"
