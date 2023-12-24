---
layout: post
title: Authority
categories:
- HackTheBox
- Medium
img_path: "/assets/img/Authority/"
image: Authority.png
permalink: "/authority/"
tags:
- Active Directory
- Reutilización de contraseñas
- Misconfiguration
- Certificados
date: 2023-12-24 13:02 +0100
---
Authority es una máquina `Windows` de nivel medio que destaca los riesgos asociados con las configuraciones incorrectas, la reutilización de contraseñas y el almacenamiento de credenciales en recursos compartidos. Además, demuestra cómo la configuración predeterminada de `Active Directory`, como la capacidad de que todos los usuarios del dominio agreguen hasta 10 equipos al dominio, puede combinarse con otras vulnerabilidades, como plantillas de certificados `AD CS`, para tomar el control total de un dominio.


## 🔍 **ENUMERACIÓN**

Empezamos enumerando todos los puertos abiertos de la máquina.

```
nmap -p- --open -sS --min-rate 5000 -n -vvv -Pn 10.129.229.56 -oG allPorts
PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack ttl 127
80/tcp    open  http             syn-ack ttl 127
88/tcp    open  kerberos-sec     syn-ack ttl 127
135/tcp   open  msrpc            syn-ack ttl 127
139/tcp   open  netbios-ssn      syn-ack ttl 127
389/tcp   open  ldap             syn-ack ttl 127
445/tcp   open  microsoft-ds     syn-ack ttl 127
464/tcp   open  kpasswd5         syn-ack ttl 127
593/tcp   open  http-rpc-epmap   syn-ack ttl 127
636/tcp   open  ldapssl          syn-ack ttl 127
3268/tcp  open  globalcatLDAP    syn-ack ttl 127
3269/tcp  open  globalcatLDAPssl syn-ack ttl 127
5985/tcp  open  wsman            syn-ack ttl 127
8443/tcp  open  https-alt        syn-ack ttl 127
9389/tcp  open  adws             syn-ack ttl 127
47001/tcp open  winrm            syn-ack ttl 127
49664/tcp open  unknown          syn-ack ttl 127
49665/tcp open  unknown          syn-ack ttl 127
49666/tcp open  unknown          syn-ack ttl 127
49667/tcp open  unknown          syn-ack ttl 127
49671/tcp open  unknown          syn-ack ttl 127
49674/tcp open  unknown          syn-ack ttl 127
49675/tcp open  unknown          syn-ack ttl 127
49679/tcp open  unknown          syn-ack ttl 127
49680/tcp open  unknown          syn-ack ttl 127
49686/tcp open  unknown          syn-ack ttl 127
49687/tcp open  unknown          syn-ack ttl 127
49699/tcp open  unknown          syn-ack ttl 127
49717/tcp open  unknown          syn-ack ttl 127
```

Una vez que conocemos los puertos abiertos, realizamos un escaneo más exhaustivo para conocer la versión y servicio de cada puerto.

```
nmap -p53,80,88,135,139,389,445,464,593,636,3268,3269,5985,8443,9389,47001,49664,49665,49666,49667,49671,49674,49675,49679,49680,49686,49687,49699,49717 -sCV 10.129.229.56 -oN targeted

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-12-22 19:46:53Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: othername: UPN::AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
|_ssl-date: 2023-12-22T19:47:59+00:00; +4h00m00s from scanner time.
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
|_ssl-date: 2023-12-22T19:48:00+00:00; +4h00m00s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: othername: UPN::AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: othername: UPN::AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
|_ssl-date: 2023-12-22T19:47:59+00:00; +4h00m00s from scanner time.
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: othername: UPN::AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
|_ssl-date: 2023-12-22T19:48:00+00:00; +4h00m00s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
8443/tcp  open  ssl/https-alt
|_ssl-date: TLS randomness does not represent time
|_http-title: Site doesn't have a title (text/html;charset=ISO-8859-1).
| fingerprint-strings: 
|   FourOhFourRequest, GetRequest: 
|     HTTP/1.1 200 
|     Content-Type: text/html;charset=ISO-8859-1
|     Content-Length: 82
|     Date: Fri, 22 Dec 2023 19:47:00 GMT
|     Connection: close
|     <html><head><meta http-equiv="refresh" content="0;URL='/pwm'"/></head></html>
|   HTTPOptions: 
|     HTTP/1.1 200 
|     Allow: GET, HEAD, POST, OPTIONS
|     Content-Length: 0
|     Date: Fri, 22 Dec 2023 19:47:00 GMT
|     Connection: close
|   RTSPRequest: 
|     HTTP/1.1 400 
|     Content-Type: text/html;charset=utf-8
|     Content-Language: en
|     Content-Length: 1936
|     Date: Fri, 22 Dec 2023 19:47:06 GMT
|     Connection: close
|     <!doctype html><html lang="en"><head><title>HTTP Status 400 
|     Request</title><style type="text/css">body {font-family:Tahoma,Arial,sans-serif;} h1, h2, h3, b {color:white;background-color:#525D76;} h1 {font-size:22px;} h2 {font-size:16px;} h3 {font-size:14px;} p {font-size:12px;} a {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1>HTTP Status 400 
|_    Request</h1><hr class="line" /><p><b>Type</b> Exception Report</p><p><b>Message</b> Invalid character found in the HTTP protocol [RTSP&#47;1.00x0d0x0a0x0d0x0a...]</p><p><b>Description</b> The server cannot or will not process the request due to something that is perceived to be a client error (e.g., malformed request syntax, invalid
| ssl-cert: Subject: commonName=172.16.2.118
| Not valid before: 2023-12-20T19:34:25
|_Not valid after:  2025-12-22T07:12:49
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49675/tcp open  msrpc         Microsoft Windows RPC
49679/tcp open  msrpc         Microsoft Windows RPC
49680/tcp open  msrpc         Microsoft Windows RPC
49686/tcp open  msrpc         Microsoft Windows RPC
49687/tcp open  msrpc         Microsoft Windows RPC
49699/tcp open  msrpc         Microsoft Windows RPC
49717/tcp open  msrpc         Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8443-TCP:V=7.94SVN%T=SSL%I=7%D=12/22%Time=6585AF74%P=x86_64-pc-linu
SF:x-gnu%r(GetRequest,DB,"HTTP/1\.1\x20200\x20\r\nContent-Type:\x20text/ht
SF:ml;charset=ISO-8859-1\r\nContent-Length:\x2082\r\nDate:\x20Fri,\x2022\x
SF:20Dec\x202023\x2019:47:00\x20GMT\r\nConnection:\x20close\r\n\r\n\n\n\n\
SF:n\n<html><head><meta\x20http-equiv=\"refresh\"\x20content=\"0;URL='/pwm
SF:'\"/></head></html>")%r(HTTPOptions,7D,"HTTP/1\.1\x20200\x20\r\nAllow:\
SF:x20GET,\x20HEAD,\x20POST,\x20OPTIONS\r\nContent-Length:\x200\r\nDate:\x
SF:20Fri,\x2022\x20Dec\x202023\x2019:47:00\x20GMT\r\nConnection:\x20close\
SF:r\n\r\n")%r(FourOhFourRequest,DB,"HTTP/1\.1\x20200\x20\r\nContent-Type:
SF:\x20text/html;charset=ISO-8859-1\r\nContent-Length:\x2082\r\nDate:\x20F
SF:ri,\x2022\x20Dec\x202023\x2019:47:00\x20GMT\r\nConnection:\x20close\r\n
SF:\r\n\n\n\n\n\n<html><head><meta\x20http-equiv=\"refresh\"\x20content=\"
SF:0;URL='/pwm'\"/></head></html>")%r(RTSPRequest,82C,"HTTP/1\.1\x20400\x2
SF:0\r\nContent-Type:\x20text/html;charset=utf-8\r\nContent-Language:\x20e
SF:n\r\nContent-Length:\x201936\r\nDate:\x20Fri,\x2022\x20Dec\x202023\x201
SF:9:47:06\x20GMT\r\nConnection:\x20close\r\n\r\n<!doctype\x20html><html\x
SF:20lang=\"en\"><head><title>HTTP\x20Status\x20400\x20\xe2\x80\x93\x20Bad
SF:\x20Request</title><style\x20type=\"text/css\">body\x20{font-family:Tah
SF:oma,Arial,sans-serif;}\x20h1,\x20h2,\x20h3,\x20b\x20{color:white;backgr
SF:ound-color:#525D76;}\x20h1\x20{font-size:22px;}\x20h2\x20{font-size:16p
SF:x;}\x20h3\x20{font-size:14px;}\x20p\x20{font-size:12px;}\x20a\x20{color
SF::black;}\x20\.line\x20{height:1px;background-color:#525D76;border:none;
SF:}</style></head><body><h1>HTTP\x20Status\x20400\x20\xe2\x80\x93\x20Bad\
SF:x20Request</h1><hr\x20class=\"line\"\x20/><p><b>Type</b>\x20Exception\x
SF:20Report</p><p><b>Message</b>\x20Invalid\x20character\x20found\x20in\x2
SF:0the\x20HTTP\x20protocol\x20\[RTSP&#47;1\.00x0d0x0a0x0d0x0a\.\.\.\]</p>
SF:<p><b>Description</b>\x20The\x20server\x20cannot\x20or\x20will\x20not\x
SF:20process\x20the\x20request\x20due\x20to\x20something\x20that\x20is\x20
SF:perceived\x20to\x20be\x20a\x20client\x20error\x20\(e\.g\.,\x20malformed
SF:\x20request\x20syntax,\x20invalid\x20");
Service Info: Host: AUTHORITY; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 3h59m59s, deviation: 0s, median: 3h59m59s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2023-12-22T19:47:54
|_  start_date: N/A
```

### SMB

Utilizamos `smbmap` para ver los recursos compartidos y a cuáles podemos acceder sin credenciales.

![](Pasted image 20231222183028.png)

Tenemos acceso al recurso `Development`, por lo que podemos acceder al recurso y descargarnos todo lo que haya dentro para mayor comodidad.

![](Pasted image 20231222185806.png)
![](20231222185858.png)

### Web - 8443

Tenemos un servicio web en el que podemos ver un panel de autenticación, pero no disponemos de credenciales. Podemos observar que está utilizando `PWM`, el cual tenemos acceso a un archivo dentro del recurso compartido que nos hemos descargado.

![](Pasted image 20231222191011.png)
![](Pasted image 20231222192358.png)

Vemos que hay una serie de credenciales cifradas con `Ansible Vault`. Vamos a guardar cada una en archivos diferentes para más adelante obtener su contenido.

![](Pasted image 20231222192427.png)

Utilizamos `ansible2john` para poder crackear los hashes con la herramienta `john`.

![](Pasted image 20231222192556.png)
![](Pasted image 20231222192318.png)

Una vez que tenemos los hashes crackeados, tenemos que instalar la utilidad `ansible-vault` para poder descifrar el contenido.

```
pip3 install ansible-vault
```

![](Pasted image 20231222193143.png)

Una vez que tenemos el contenido, podemos acceder a través del `Configuration Manager`.

![](Pasted image 20231222193536.png)


## 💣 **EXPLOTACIÓN**

Dentro de `LDAP/LDAP Directories/default/Connection`, podemos cambiar la dirección a la que se conecta al `ldap` de la máquina por nuestra dirección, por lo que podemos ponernos a la escucha en nuestra máquina y ver que recibimos.

![](Pasted image 20231222194024.png)
![](Pasted image 20231222194105.png)

Vemos que hemos obtenido una cadena con el usuario `svc_ldap` perteneciente al dominio y lo que parece una contraseña. Si probamos la contraseña con `crackmapexec` a través de `winrm`, vemos que la contraseña es válida y además podemos obtener una shell a través de `evil-winrm` gracias a que el usuario `svc_ldap` pertenece al grupo `Remote Management Users`.

![](Pasted image 20231222194439.png)
![](Pasted image 20231222194548.png)

## 🔓 **ESCALADA DE PRIVILEGIOS**

Vamos a utilizar la herramienta `certipy`, que nos permite obtener las plantillas de certificados disponibles en el dominio e intentar encontrar alguna vulnerabilidad en ellas.

![](Pasted image 20231223140608.png)

En la plantilla `CorpVPN` tenemos la vulnerabilidad `ESC1`, la cual nos permite añadir un equipo al dominio sin necesidad de ser un usuario privilegiado.

![](Pasted image 20231223140837.png)

Haciendo uso de la herramienta `impacket-addcomputer` añadimos un ordenador al dominio a través de `LDAPS`

![](Pasted image 20231223154643.png)

Una vez añadido, podemos obtener el certificado del usuario `administrator` gracias a la herramienta `certipy`.

![](Pasted image 20231223155505.png)

El archivo obtenido contiene tanto el certificado como la clave privada del usuario `administrator`, por lo que vamos a separarlas con `certipy`.

![](Pasted image 20231223155856.png)

Podemos hacer uso de la herramienta [PassTheCert](https://github.com/AlmondOffSec/PassTheCert) para interactuar con `ldap` y utilizar el certificado y la clave privada obtenida como método de acceso.

![](Pasted image 20231223160125.png)

Utilizando la opción `-action whoami` podemos ver nos logueamos como el usuario `Administrator`, por lo que vamos a ejecutar una shell en `ldap` para añadir al usuario `svc_ldap` al grupo `Domain Admins`.

![](Pasted image 20231223160307.png)

Una vez añadido el usuario al grupo, utilizamos `impacket-psexec` para conectarnos y obtener una shell como `nt authority\system`.

![](Pasted image 20231223160615.png)
