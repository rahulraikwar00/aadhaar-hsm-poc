#!/bin/sh
# Create directory for tokens
mkdir -p /var/lib/softhsm/tokens

# Create config file
cat > /etc/softhsm2.conf << 'CONF'
directories.tokendir = /var/lib/softhsm/tokens
objectstore.backend = file
log.level = INFO
CONF

export SOFTHSM2_CONF=/etc/softhsm2.conf

# Initialize token (use --free to find available slot)
softhsm2-util --init-token --free --label AuthToken --so-pin 87654321 --pin 12345678 --force

# Show slots to verify
softhsm2-util --show-slots

# Keep container running
tail -f /dev/null
EOF
