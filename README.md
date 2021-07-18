# stateless-gpg
http://edgecase.net/articles/gpg_1410_stateless_operations

Python 3.5.2

Pytest 6.1.2

Git 1.x, preferably Git 1.4.x.


# Installing GPG


Check versions:

```
stjohn@edgecase2:~$ gpg --version
gpg (GnuPG) 2.2.19
libgcrypt 1.8.5


stjohn@edgecase2:~$ gpgv1 --version
gpgv (GnuPG) 1.4.23
```


Search for available versions:

```apt search ^gpg```

Example results:

```
gpgv/xenial-updates,xenial-security,now 1.4.20-1ubuntu3.3 amd64 [installed]
  GNU privacy guard - signature verification tool

gpgv2/xenial-updates,xenial-security 2.1.11-6ubuntu2.1 amd64
  GNU privacy guard - signature verification tool (new v2.x)

gpgv1/focal 1.4.23-1 amd64
  GNU privacy guard - signature verification tool (deprecated "classic" version)
```


Install old version:
```sudo apt-get install gpgv1```
