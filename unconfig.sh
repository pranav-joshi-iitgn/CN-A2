#!/bin/bash

# The line to remove
OLD_NAMESERVER="nameserver 10.0.0.6"

# The file to modify
RESOLV_CONF="/etc/resolv.conf"

# Use grep to check if the line exists in the file.
if grep -q "^$OLD_NAMESERVER" "$RESOLV_CONF"; then
  echo "Removing '$OLD_NAMESERVER' from $RESOLV_CONF"
  
  # Use sed to delete the line that starts with the nameserver entry.
  # The -i option edits the file in-place.
  # The '/^pattern/d' command tells sed to delete any line that matches the pattern.
  sed -i "/^$OLD_NAMESERVER/d" "$RESOLV_CONF"
else
  echo "'$OLD_NAMESERVER' is not present in $RESOLV_CONF"
fi
