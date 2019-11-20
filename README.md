# RTL 8196D/E 기반 WebRedir 기능 구현

Client의 웹 페이지 요청에 대해서 특정 URL은 허용, 나머지는 차단하여 클라이언트 웹 페이지 요청 패킷을 후킹,

해당 패킷을 공유기 자체 웹 서버로 전달하여 Redirection URL 클라이언트로 응답하는 기능 구현

# 프로젝트 정보

## 1. 설치

(필수)
VirtualBox

Ubuntu-14.04.1-desktop-i386.iso

(선택사항)
tftpd

teraterm

winscp

putty

## 2. 사용 방법

0) Linux에 해당 패키지를 설치하십시오
libncurses5-dev

build-essential

gwak

bison

zlib1g-dev

1. busybox의 설정에서 httpd 사용함으로 설정
2. goagead 또는 boa 웹서버의 set_firewall.c에 다음 함수를 추가

``` int set_web_redir()

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

    if (1) /* 사용자가(웹서버 UI 메뉴) 설정한 사용 여부 설정 값과 연동 */

    {
        system("httpd -p 81 -h /var/web");

        fp = fopen("/var/web/index.html", "w");
        if (fp)

        {
            fprintf(fp, "<frameset>\n");
            /* src에 사용자가 설정한 redirection할 웹 사이트 값 연동 */
            fprintf(fp, "<frame name='CONTENT' src='http://www.iotek.co.kr' frameborder='0'>\n");
            fprintf(fp, "</frameset>\n");
            fclose(fp);
        }

        fp = fopen("/var/web_redir.sh", "w");
        if (fp)

        {
            apmib_get(MIB_IP_ADDR,  &lan_addr);
            strcpy(strLanIp, inet_ntoa(*((struct in_addr *)&lan_addr)));
            /* iptables rule 실행 스크립트 생성 */
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
}
```

3. setFirewallIptablesRules() 함수 내에서 set_web_redir() 함수를 호출
``` #if 1
	apmib_get(MIB_WEB_REDIR_EN, (void *)&intVal);
		set_web_redir();
}

#endif
	return 0;
}
```

4. mibdef 
``` MIBDEF(unsigned char, web_redir_en, , WEB_REDIR_EN, BYTE_T, APMIB_T, 0, 0)
MIBDEF(unsigned char, web_redir_rul, [40], WEB_REDIR_URL, STRING_T, APMIB_T, 0, 0)
```

참조 파일경로
users/goahead-2.1.1/LINUX/mibdef.h
users/goahead-2.1.1/LINUX/system/set_firewall
