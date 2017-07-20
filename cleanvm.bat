taskkill /im vmware-vmx.exe /f
forfiles /M *.lck /C "cmd /c rmdir /S /Q @path"
del *.vmem *.dmp *.log
