# pam_sqlite3

#### Description

This module provides support for authenticating with SQLite for OpenVPN.


#### Installation

1. \# cd pam_sqlite3
2. \# make
3. \# cp pam_sqlite3.so /lib64/security/

#### Setting

1. create pam service

```
# /etc/pam.d/openvpn
# crypt:  
# 0 = No encryption  
# 1 = md5  
# 2 = sha1  
auth        required    pam_sqlite3.so db=/etc/openvpn/openvpn.db table=t_user user=username passwd=password active=1 expire=expire crypt=1
account     required    pam_sqlite3.so db=/etc/openvpn/openvpn.db table=t_user user=username passwd=password active=1 expire=expire crypt=1
```



2. create sqlite3 file

```
/etc/openvpn/openvpn.db

create table t_user (
     username text not null, 
     password text not null, 
     active int, 
     expire text
);
```
