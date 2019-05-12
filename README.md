# pam_sqlite3

#### 说明

此模块提供对针对OpenVPN利用SQLite进行身份验证的支持。


#### 安装

1. \# cd pam_sqlite3
2. \# make
3. \# cp pam_sqlite3.so /lib64/security/

#### 设置

1. 创建服务认证

```
# /etc/pam.d/openvpn
# crypt:  
# 0 = No encryption  
# 1 = md5  
# 2 = sha1  
auth        required    pam_sqlite3.so db=/etc/openvpn/openvpn.db table=t_user user=username passwd=password expire=expire crypt=1
account     required    pam_sqlite3.so db=/etc/openvpn/openvpn.db table=t_user user=username passwd=password expire=expire crypt=1
```


2. 创建sqlite3数据库

```
/etc/openvpn/openvpn.db

create table t_user (
     username text not null, 
     password text not null, 
     active int, 
     expire text
);
```
