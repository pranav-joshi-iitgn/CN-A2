#!/bin/bash

RESOLV_CONF="/etc/resolv.conf"
NAMESERVER_LINE="nameserver 10.0.0.6"

# Check if the line already exists in resolv.conf
if ! grep -q "^${NAMESERVER_LINE}$" "$RESOLV_CONF"; then
    echo "Adding '${NAMESERVER_LINE}' to the top of ${RESOLV_CONF}..."
    # Create a temporary file with the new line at the top, then append the original content
    echo "${NAMESERVER_LINE}" | cat - "$RESOLV_CONF" > "${RESOLV_CONF}.tmp" && mv "${RESOLV_CONF}.tmp" "$RESOLV_CONF"
    echo "Done."
else
    echo "'${NAMESERVER_LINE}' already exists in ${RESOLV_CONF}. No changes made."
fi