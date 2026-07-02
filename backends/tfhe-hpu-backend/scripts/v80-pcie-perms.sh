  #!/usr/bin/env bash
   
GROUP=hw;
# Enable Pcie rescan
if [ -e /sys/bus/pci/rescan ]; then
  sudo --stdin /usr/bin/chgrp $GROUP /sys/bus/pci/rescan && sudo --stdin /usr/bin/chmod g+w /sys/bus/pci/rescan
fi
# Search V80 pcie boards PF0
for dev in $(lspci -nn -d 10ee:50b4 | awk '{print $1}'); do
  sudo --stdin /usr/bin/chgrp -R $GROUP /sys/bus/pci/devices/0000\:$dev/
  sudo --stdin /usr/bin/chmod -R g=u    /sys/bus/pci/devices/0000\:$dev/
done
# Search V80 pcie boards PF1
for dev in $(lspci -nn -d 10ee:50b5 | awk '{print $1}'); do
  sudo --stdin /usr/bin/chgrp -R $GROUP /sys/bus/pci/devices/0000\:$dev/
  sudo --stdin /usr/bin/chmod -R g=u    /sys/bus/pci/devices/0000\:$dev/
done
