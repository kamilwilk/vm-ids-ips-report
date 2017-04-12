# vm-ids-ips-report

## Python script which pulls VMs from vSphere and creates a report comparing the list of hosts found in Qualys and TripWire

### Not clean code, but it was created quickly for a specific use case and it performed without issues.

### Dependencies:
* Python 2.7
* pip (Python package manager)
  https://pip.pypa.io/en/latest/installing/#using-package-managers
* pyvmomi (vSphere API available on GitHub and through pip)
  https://github.com/vmware/pyvmomi
* qualysapi (Qualys API available on GitHub and through pip)
  https://github.com/paragbaxi/qualysapi
* tools folder from pyvmomi Community Samples (available on GitHub)
	https://github.com/vmware/pyvmomi-community-samples
