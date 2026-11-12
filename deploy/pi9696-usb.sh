#!/bin/sh
# Mounts a plugged-in USB drive at /media/usb, where the app looks for its
# copy, format and config export/import target. Run by pi9696-usb@.service,
# which the udev rule starts for each USB block device carrying a filesystem.
#
#   pi9696-usb.sh start|stop <kernel name, e.g. sda1>
set -u
MP=${PI9696_USB_MP:-/media/usb} # override for usbmount_test.go only
DEV="/dev/$2"

case "$1" in
start)
  mkdir -p "$MP"
  # One drive at a time: the first one plugged in keeps the mountpoint.
  mountpoint -q "$MP" && { echo "$MP busy, leaving $DEV unmounted"; exit 0; }
  # Never a disk the system is using (a USB-booted Pi's root SSD): the app's
  # Format would wipe it.
  disk=$(lsblk -ndo PKNAME "$DEV" 2>/dev/null)
  [ -n "$disk" ] || disk=$2
  if lsblk -nro MOUNTPOINT "/dev/$disk" | grep -q .; then
    echo "$DEV is on in-use disk /dev/$disk, not mounting"
    exit 0
  fi
  exec mount "$DEV" "$MP"
  ;;
stop)
  # Only our own mount: a second drive that was skipped must not unmount the
  # first when it is pulled. Lazy, since the device is usually already gone.
  if [ "$(findmnt -rn -M "$MP" -o SOURCE)" = "$DEV" ]; then
    umount -l "$MP"
  fi
  ;;
esac
exit 0
