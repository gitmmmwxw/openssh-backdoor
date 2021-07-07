# openssh-backdoor

--with-ssl-dir=PATH 


 
 ./configure --prefix=/opt/ssh --sysconfdir=/opt/ssh/etc --with-ssl-dir=PATH 
 https://www.linuxfromscratch.org/blfs/view/7.9/postlfs/openssh.html
 
 ./config --prefix=/root/openssl-1.0.1u/bin no-asm  -fPIC no-shared
make
make install
