/*++

Module Name:

    redirectctl.c

Abstract:

    User-mode CLI tool to manage IPv4/IPv6 IP and port redirect rules
    for the NDISLWF filter driver.

--*/

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FILTER_USER_REDIRECT_ONLY
#include "filteruser.h"

#define FILTER_DEVICE_PATH  "\\\\.\\NDISLWF"

static
VOID
PrintUsage(
    VOID
    )
{
    printf("Usage:\n");
    printf("  redirectctl add <ipv4|ipv6> <tcp|udp|any> <orig_ip> <orig_port> <new_ip> <new_port> [--mac <xx:xx:xx:xx:xx:xx>] [--local] [--id <rule_id>]\n");
    printf("  redirectctl del <rule_id>\n");
    printf("  redirectctl clear\n");
    printf("  redirectctl list\n");
    printf("\nNotes:\n");
    printf("  - orig_port = 0 matches any destination port.\n");
    printf("  - new_port  = 0 keeps original destination port.\n");
    printf("  - --mac is required when redirecting to a different host in the same subnet.\n");
    printf("  - --local forces local-host loopback redirect (also auto-detected when new_ip matches adapter IP).\n");
    printf("  - MAC accepts ':' or '-' separators (e.g. aa:bb:cc:dd:ee:ff).\n");
}

static
BOOL
ParseIpAddress(
    IN  UCHAR               AddressFamily,
    IN  const char         *Text,
    OUT PREDIRECT_IP_ADDR   OutAddr
    )
{
    char            Buf[128];
    INT             SockAddrLen;

    memset(OutAddr, 0, sizeof(REDIRECT_IP_ADDR));

    if (strlen(Text) >= sizeof(Buf))
    {
        return FALSE;
    }
    strcpy(Buf, Text);

    if (AddressFamily == REDIRECT_AF_IPV4)
    {
        struct sockaddr_in  Sin;
        memset(&Sin, 0, sizeof(Sin));
        SockAddrLen = (INT)sizeof(Sin);
        if (WSAStringToAddressA(Buf, AF_INET, NULL, (LPSOCKADDR)&Sin, &SockAddrLen) != 0)
        {
            return FALSE;
        }
        memcpy(OutAddr->V4, &Sin.sin_addr, 4);
        return TRUE;
    }
    else if (AddressFamily == REDIRECT_AF_IPV6)
    {
        struct sockaddr_in6 Sin6;
        memset(&Sin6, 0, sizeof(Sin6));
        SockAddrLen = (INT)sizeof(Sin6);
        if (WSAStringToAddressA(Buf, AF_INET6, NULL, (LPSOCKADDR)&Sin6, &SockAddrLen) != 0)
        {
            return FALSE;
        }
        memcpy(OutAddr->V6, &Sin6.sin6_addr, 16);
        return TRUE;
    }

    return FALSE;
}

static
VOID
FormatIpAddress(
    IN  UCHAR                   AddressFamily,
    IN  const REDIRECT_IP_ADDR *Addr,
    OUT char                   *OutBuf,
    IN  DWORD                   OutBufLen
    )
{
    DWORD   StrLen = OutBufLen;

    if (AddressFamily == REDIRECT_AF_IPV4)
    {
        struct sockaddr_in  Sin;
        memset(&Sin, 0, sizeof(Sin));
        Sin.sin_family = AF_INET;
        memcpy(&Sin.sin_addr, Addr->V4, 4);
        if (WSAAddressToStringA((LPSOCKADDR)&Sin, sizeof(Sin), NULL, OutBuf, &StrLen) != 0)
        {
            _snprintf(OutBuf, OutBufLen - 1, "<invalid>");
            OutBuf[OutBufLen - 1] = '\0';
        }
    }
    else
    {
        struct sockaddr_in6 Sin6;
        memset(&Sin6, 0, sizeof(Sin6));
        Sin6.sin6_family = AF_INET6;
        memcpy(&Sin6.sin6_addr, Addr->V6, 16);
        if (WSAAddressToStringA((LPSOCKADDR)&Sin6, sizeof(Sin6), NULL, OutBuf, &StrLen) != 0)
        {
            _snprintf(OutBuf, OutBufLen - 1, "<invalid>");
            OutBuf[OutBufLen - 1] = '\0';
        }
    }
}

static
BOOL
ParsePort(
    IN  const char *Text,
    OUT PUSHORT     PortNetOrder
    )
{
    char   *EndPtr = NULL;
    ULONG   Val;

    if (Text[0] == '\0' || Text[0] == '-')
    {
        return FALSE;
    }

    Val = strtoul(Text, &EndPtr, 10);
    if (EndPtr == Text || *EndPtr != '\0' || Val > 65535UL)
    {
        return FALSE;
    }

    *PortNetOrder = htons((USHORT)Val);
    return TRUE;
}

static
BOOL
ParseMacAddress(
    IN  const char *Text,
    OUT UCHAR       Mac[6]
    )
{
    UINT    Bytes[6];
    char    Extra;
    INT     Matched;
    INT     i;

    Matched = sscanf(
                  Text,
                  "%2x:%2x:%2x:%2x:%2x:%2x%c",
                  &Bytes[0], &Bytes[1], &Bytes[2],
                  &Bytes[3], &Bytes[4], &Bytes[5],
                  &Extra);
    if (Matched != 6)
    {
        Matched = sscanf(
                      Text,
                      "%2x-%2x-%2x-%2x-%2x-%2x%c",
                      &Bytes[0], &Bytes[1], &Bytes[2],
                      &Bytes[3], &Bytes[4], &Bytes[5],
                      &Extra);
    }

    if (Matched != 6)
    {
        return FALSE;
    }

    for (i = 0; i < 6; i++)
    {
        if (Bytes[i] > 0xFF)
        {
            return FALSE;
        }
        Mac[i] = (UCHAR)Bytes[i];
    }

    return TRUE;
}

static
HANDLE
OpenFilterDevice(
    VOID
    )
{
    HANDLE hDev = CreateFileA(
                      FILTER_DEVICE_PATH,
                      GENERIC_READ | GENERIC_WRITE,
                      0,
                      NULL,
                      OPEN_EXISTING,
                      FILE_ATTRIBUTE_NORMAL,
                      NULL);
    if (hDev == INVALID_HANDLE_VALUE)
    {
        printf("Failed to open %s (Win32 error %lu).\n", FILTER_DEVICE_PATH, GetLastError());
    }
    return hDev;
}

static
int
CmdAdd(
    IN HANDLE   hDev,
    IN int      argc,
    IN char    *argv[]
    )
{
    REDIRECT_RULE   Rule;
    REDIRECT_RULE   OutRule;
    DWORD           BytesReturned = 0;
    int             i;

    if (argc < 8)
    {
        PrintUsage();
        return 1;
    }

    memset(&Rule, 0, sizeof(Rule));
    memset(&OutRule, 0, sizeof(OutRule));

    if (_stricmp(argv[2], "ipv4") == 0 || _stricmp(argv[2], "v4") == 0)
    {
        Rule.AddressFamily = REDIRECT_AF_IPV4;
    }
    else if (_stricmp(argv[2], "ipv6") == 0 || _stricmp(argv[2], "v6") == 0)
    {
        Rule.AddressFamily = REDIRECT_AF_IPV6;
    }
    else
    {
        printf("Invalid address family: %s\n", argv[2]);
        return 1;
    }

    if (_stricmp(argv[3], "tcp") == 0)
    {
        Rule.Protocol = REDIRECT_PROTO_TCP;
    }
    else if (_stricmp(argv[3], "udp") == 0)
    {
        Rule.Protocol = REDIRECT_PROTO_UDP;
    }
    else if (_stricmp(argv[3], "any") == 0)
    {
        Rule.Protocol = REDIRECT_PROTO_ANY;
    }
    else
    {
        printf("Invalid protocol: %s\n", argv[3]);
        return 1;
    }

    if (!ParseIpAddress(Rule.AddressFamily, argv[4], &Rule.OrigIp))
    {
        printf("Invalid orig_ip: %s\n", argv[4]);
        return 1;
    }

    if (!ParsePort(argv[5], &Rule.OrigPort))
    {
        printf("Invalid orig_port: %s\n", argv[5]);
        return 1;
    }

    if (!ParseIpAddress(Rule.AddressFamily, argv[6], &Rule.NewIp))
    {
        printf("Invalid new_ip: %s\n", argv[6]);
        return 1;
    }

    if (!ParsePort(argv[7], &Rule.NewPort))
    {
        printf("Invalid new_port: %s\n", argv[7]);
        return 1;
    }

    for (i = 8; i < argc; i++)
    {
        if (_stricmp(argv[i], "--mac") == 0 && i + 1 < argc)
        {
            if (!ParseMacAddress(argv[++i], Rule.NewDstMac))
            {
                printf("Invalid MAC address: %s\n", argv[i]);
                return 1;
            }
            Rule.Flags |= REDIRECT_FLAG_REWRITE_MAC;
        }
        else if (_stricmp(argv[i], "--local") == 0)
        {
            Rule.Flags |= REDIRECT_FLAG_LOCAL_LOOPBACK;
        }
        else if (_stricmp(argv[i], "--id") == 0 && i + 1 < argc)
        {
            char *EndPtr = NULL;
            Rule.RuleId = strtoul(argv[++i], &EndPtr, 10);
            if (EndPtr == argv[i] || *EndPtr != '\0')
            {
                printf("Invalid rule_id: %s\n", argv[i]);
                return 1;
            }
        }
        else
        {
            printf("Unknown or incomplete option: %s\n", argv[i]);
            return 1;
        }
    }

    if (!DeviceIoControl(
             hDev,
             IOCTL_FILTER_ADD_REDIRECT_RULE,
             &Rule,
             sizeof(Rule),
             &OutRule,
             sizeof(OutRule),
             &BytesReturned,
             NULL))
    {
        printf("IOCTL_FILTER_ADD_REDIRECT_RULE failed (Win32 error %lu).\n", GetLastError());
        return 1;
    }

    printf("Rule added successfully. RuleId = %lu\n",
           (BytesReturned >= sizeof(OutRule)) ? OutRule.RuleId : Rule.RuleId);
    return 0;
}

static
int
CmdDel(
    IN HANDLE   hDev,
    IN int      argc,
    IN char    *argv[]
    )
{
    REDIRECT_DEL_RULE   Req;
    char               *EndPtr = NULL;
    DWORD               BytesReturned = 0;

    if (argc != 3)
    {
        PrintUsage();
        return 1;
    }

    Req.RuleId = strtoul(argv[2], &EndPtr, 10);
    if (EndPtr == argv[2] || *EndPtr != '\0' || Req.RuleId == 0)
    {
        printf("Invalid rule_id: %s\n", argv[2]);
        return 1;
    }

    if (!DeviceIoControl(
             hDev,
             IOCTL_FILTER_DEL_REDIRECT_RULE,
             &Req,
             sizeof(Req),
             NULL,
             0,
             &BytesReturned,
             NULL))
    {
        printf("IOCTL_FILTER_DEL_REDIRECT_RULE failed (Win32 error %lu).\n", GetLastError());
        return 1;
    }

    printf("Rule %lu deleted.\n", Req.RuleId);
    return 0;
}

static
int
CmdClear(
    IN HANDLE   hDev
    )
{
    DWORD BytesReturned = 0;

    if (!DeviceIoControl(
             hDev,
             IOCTL_FILTER_CLEAR_REDIRECT_RULES,
             NULL,
             0,
             NULL,
             0,
             &BytesReturned,
             NULL))
    {
        printf("IOCTL_FILTER_CLEAR_REDIRECT_RULES failed (Win32 error %lu).\n", GetLastError());
        return 1;
    }

    printf("All redirect rules cleared.\n");
    return 0;
}

static
int
CmdList(
    IN HANDLE   hDev
    )
{
    REDIRECT_RULE   Rules[MAX_REDIRECT_RULES];
    DWORD           BytesReturned = 0;
    ULONG           Count;
    ULONG           i;

    if (!DeviceIoControl(
             hDev,
             IOCTL_FILTER_LIST_REDIRECT_RULES,
             NULL,
             0,
             Rules,
             sizeof(Rules),
             &BytesReturned,
             NULL))
    {
        printf("IOCTL_FILTER_LIST_REDIRECT_RULES failed (Win32 error %lu).\n", GetLastError());
        return 1;
    }

    Count = BytesReturned / sizeof(REDIRECT_RULE);
    if (Count == 0)
    {
        printf("No redirect rules configured.\n");
        return 0;
    }

    printf("Total %lu rule(s):\n", Count);
    for (i = 0; i < Count; i++)
    {
        char        OrigStr[64];
        char        NewStr[64];
        const char *AfStr = (Rules[i].AddressFamily == REDIRECT_AF_IPV6) ? "IPv6" : "IPv4";
        const char *ProtoStr;

        if (Rules[i].Protocol == REDIRECT_PROTO_TCP)
        {
            ProtoStr = "TCP";
        }
        else if (Rules[i].Protocol == REDIRECT_PROTO_UDP)
        {
            ProtoStr = "UDP";
        }
        else
        {
            ProtoStr = "ANY";
        }

        FormatIpAddress(Rules[i].AddressFamily, &Rules[i].OrigIp, OrigStr, sizeof(OrigStr));
        FormatIpAddress(Rules[i].AddressFamily, &Rules[i].NewIp, NewStr, sizeof(NewStr));

        printf("  [%lu] %s %s %s:%u -> %s:%u",
               Rules[i].RuleId,
               AfStr,
               ProtoStr,
               OrigStr,
               (UINT)ntohs(Rules[i].OrigPort),
               NewStr,
               (UINT)ntohs(Rules[i].NewPort));

        if ((Rules[i].Flags & REDIRECT_FLAG_REWRITE_MAC) != 0)
        {
            printf(" (DstMAC=%02X:%02X:%02X:%02X:%02X:%02X)",
                   Rules[i].NewDstMac[0], Rules[i].NewDstMac[1], Rules[i].NewDstMac[2],
                   Rules[i].NewDstMac[3], Rules[i].NewDstMac[4], Rules[i].NewDstMac[5]);
        }
        if ((Rules[i].Flags & REDIRECT_FLAG_LOCAL_LOOPBACK) != 0)
        {
            printf(" [LOCAL]");
        }
        printf("\n");
    }

    return 0;
}

int
__cdecl
main(
    int     argc,
    char   *argv[]
    )
{
    WSADATA WsaData;
    HANDLE  hDev;
    int     Ret = 1;

    if (argc < 2)
    {
        PrintUsage();
        return 1;
    }

    if (WSAStartup(MAKEWORD(2, 2), &WsaData) != 0)
    {
        printf("WSAStartup failed.\n");
        return 1;
    }

    hDev = OpenFilterDevice();
    if (hDev != INVALID_HANDLE_VALUE)
    {
        if (_stricmp(argv[1], "add") == 0)
        {
            Ret = CmdAdd(hDev, argc, argv);
        }
        else if (_stricmp(argv[1], "del") == 0)
        {
            Ret = CmdDel(hDev, argc, argv);
        }
        else if (_stricmp(argv[1], "clear") == 0)
        {
            Ret = CmdClear(hDev);
        }
        else if (_stricmp(argv[1], "list") == 0)
        {
            Ret = CmdList(hDev);
        }
        else
        {
            PrintUsage();
            Ret = 1;
        }

        CloseHandle(hDev);
    }

    WSACleanup();
    return Ret;
}
