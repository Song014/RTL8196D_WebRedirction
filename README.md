# RTL 8196D/E ��� WebRedir ��� ����

Client�� �� ������ ��û�� ���ؼ� Ư�� URL�� ���, �������� �����Ͽ� Ŭ���̾�Ʈ �� ������ ��û ��Ŷ�� ��ŷ, �ش� ��Ŷ�� ������ ��ü �� ������ �����Ͽ� Redirection URL Ŭ���̾�Ʈ�� �����ϴ� ��� ����

# ������Ʈ ����

## 1. ��ġ

(�ʼ�)
VirtualBox
Ubuntu-14.04.1-desktop-i386.iso

(���û���)
tftpd
teraterm
winscp
putty

## 2. ��� ���

0) Linux�� �ش� ��Ű���� ��ġ�Ͻʽÿ�
libncurses5-dev
build-essential
gwak
bison
zlib1g-dev

1) busybox�� �������� httpd ��������� ����
2) goagead �Ǵ� boa �������� set_firewall.c�� ���� �Լ��� �߰�

```int set_web_redir()

{
    int val;
    unsigned int lan_addr;
    char domain[32] = {0, };
    char strLanIp[16];
    char dest[40];
    FILE *fp;

    system("killall -q httpd");

    RunSystemCmd(NULL_FILE, Iptables, _table, nat_table, NEW, WEB_REDIR_CHAIN, NULL_STR);
    RunSystemCmd(NULL_FILE, Iptables, _table, nat_table, INSERT, PREROUTING, jump, WEB_REDIR_CHAIN, NULL_STR);
    RunSystemCmd(NULL_FILE, Iptables, _table, nat_table, FLUSH, WEB_REDIR_CHAIN, NULL_STR);

    if (1) /* ����ڰ�(������ UI �޴�) ������ ��� ���� ���� ���� ���� */

    {
        system("httpd -p 81 -h /var/web");

        fp = fopen("/var/web/index.html", "w");
        if (fp)

        {
            fprintf(fp, "<frameset>\n");
            /* src�� ����ڰ� ������ redirection�� �� ����Ʈ �� ���� */
            fprintf(fp, "<frame name='CONTENT' src='http://www.iotek.co.kr' frameborder='0'>\n");
            fprintf(fp, "</frameset>\n");
            fclose(fp);
        }

        fp = fopen("/var/web_redir.sh", "w");
        if (fp)

        {
            apmib_get(MIB_IP_ADDR,  &lan_addr);
            strcpy(strLanIp, inet_ntoa(*((struct in_addr *)&lan_addr)));
            /* iptables rule ���� ��ũ��Ʈ ���� */
            fprintf(fp, "#!/bin/sh\n");
            fprintf(fp, "iptables -A web_redir -t nat -p tcp -d www.iotek.co.kr -j ACCEPT\n");
            fprintf(fp, "iptables -A web_redir -t nat -p tcp -d %s --dport 80 -j DNAT --to %s:80\n", strLanIp, strLanIp);
            fprintf(fp, "iptables -A web_redir -t nat -p tcp --dport 80 -j DNAT --to %s:81\n", strLanIp);
            fclose(fp);
            chmod("/var/web_redir.sh", 0700);
            system("/var/web_redir.sh");
        }
    }

    return 0;
}```

3) setFirewallIptablesRules() �Լ� ������ set_web_redir() �Լ��� ȣ��
``` #if 1
	apmib_get(MIB_WEB_REDIR_EN, (void *)&intVal);
		set_web_redir();
}

#endif
	return 0;
}```

4) mibdef 
```MIBDEF(unsigned char, web_redir_en, , WEB_REDIR_EN, BYTE_T, APMIB_T, 0, 0)
MIBDEF(unsigned char, web_redir_rul, [40], WEB_REDIR_URL, STRING_T, APMIB_T, 0, 0)```

���� ���ϰ��
users/goahead-2.1.1/LINUX/mibdef.h
users/goahead-2.1.1/LINUX/system/set_firewall
