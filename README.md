# VMware Escape Exploit

VMware Escape Exploit before VMware WorkStation 12.5.5

Host Target: Win10 x64

Compiler: VS2013 

Test on VMware 12.5.2 build-4638234

# Known issues

* Failing to heap manipulation causes host process crash.
* Not quite elaborate because I'm not good at doing heap "fengshui" on winows LFH.

# FAQ

> Q: Error in reboot vmware after exploit or crash process.

> A: Just remove ***.lck** folder in your vm directory or wait a while and have a coffee :)

![](https://raw.githubusercontent.com/unamer/vmware_escape/master/exp.gif)
