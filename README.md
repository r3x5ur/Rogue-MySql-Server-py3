Rogue-MySql-Server for Python3.x
==================

Rogue MySql Server for Python3.x

## Step
- Modify `FILELIST` of rogue_mysql_server.py to read the victim's file, modify `PORT` to modify the listening port
- attacker exec `python rogue_mysql_server.py`
- victim exec like `mysql.exe -h 127.0.0.1 -u root -p123 --enable-local-infile --ssl-mode=DISABLED`

## Screenshots
-----
- victim origin file
![image](https://github.com/r3x5ur/Rogue-MySql-Server-py3/assets/64947085/d121eaa1-8ee7-4e86-9e41-780b17d94100)

-----
- victim
![image](https://github.com/r3x5ur/Rogue-MySql-Server-py3/assets/64947085/44c5c062-d5e0-4158-afb0-120412e02e6c)

-----
- attacker 
![image](https://github.com/r3x5ur/Rogue-MySql-Server-py3/assets/64947085/9195e120-b3dd-4217-a496-cda60c1c0956)

