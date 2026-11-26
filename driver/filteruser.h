#ifndef __FILTERUSER_H__
#define __FILTERUSER_H__

//
// Temp file to test filter
//

#define _NDIS_CONTROL_CODE(request,method) \
            CTL_CODE(FILE_DEVICE_PHYSICAL_NETCARD, request, method, FILE_ANY_ACCESS)

#define IOCTL_FILTER_RESTART_ALL            _NDIS_CONTROL_CODE(0, METHOD_BUFFERED)
#define IOCTL_FILTER_RESTART_ONE_INSTANCE   _NDIS_CONTROL_CODE(1, METHOD_BUFFERED)
#define IOCTL_FILTER_ENUERATE_ALL_INSTANCES _NDIS_CONTROL_CODE(2, METHOD_BUFFERED)
#define IOCTL_FILTER_QUERY_ALL_STAT         _NDIS_CONTROL_CODE(3, METHOD_BUFFERED)
#define IOCTL_FILTER_CLEAR_ALL_STAT         _NDIS_CONTROL_CODE(4, METHOD_BUFFERED)
#define IOCTL_FILTER_SET_OID_VALUE          _NDIS_CONTROL_CODE(5, METHOD_BUFFERED)
#define IOCTL_FILTER_QUERY_OID_VALUE        _NDIS_CONTROL_CODE(6, METHOD_BUFFERED)
#define IOCTL_FILTER_CANCEL_REQUEST         _NDIS_CONTROL_CODE(7, METHOD_BUFFERED)
#define IOCTL_FILTER_READ_DRIVER_CONFIG     _NDIS_CONTROL_CODE(8, METHOD_BUFFERED)
#define IOCTL_FILTER_WRITE_DRIVER_CONFIG    _NDIS_CONTROL_CODE(9, METHOD_BUFFERED)
#define IOCTL_FILTER_READ_ADAPTER_CONFIG    _NDIS_CONTROL_CODE(10, METHOD_BUFFERED)
#define IOCTL_FILTER_WRITE_ADAPTER_CONFIG   _NDIS_CONTROL_CODE(11, METHOD_BUFFERED)
#define IOCTL_FILTER_READ_INSTANCE_CONFIG   _NDIS_CONTROL_CODE(12, METHOD_BUFFERED)
#define IOCTL_FILTER_WRITE_INSTANCE_CONFIG  _NDIS_CONTROL_CODE(13, METHOD_BUFFERED)
#define IOCTL_FILTER_ADD_REDIRECT_RULE      _NDIS_CONTROL_CODE(14, METHOD_BUFFERED)
#define IOCTL_FILTER_DEL_REDIRECT_RULE      _NDIS_CONTROL_CODE(15, METHOD_BUFFERED)
#define IOCTL_FILTER_CLEAR_REDIRECT_RULES   _NDIS_CONTROL_CODE(16, METHOD_BUFFERED)
#define IOCTL_FILTER_LIST_REDIRECT_RULES    _NDIS_CONTROL_CODE(17, METHOD_BUFFERED)
#define IOCTL_FILTER_ADD_DNS_SPOOF_RULE     _NDIS_CONTROL_CODE(18, METHOD_BUFFERED)
#define IOCTL_FILTER_DEL_DNS_SPOOF_RULE     _NDIS_CONTROL_CODE(19, METHOD_BUFFERED)
#define IOCTL_FILTER_CLEAR_DNS_SPOOF_RULES  _NDIS_CONTROL_CODE(20, METHOD_BUFFERED)
#define IOCTL_FILTER_LIST_DNS_SPOOF_RULES   _NDIS_CONTROL_CODE(21, METHOD_BUFFERED)


#ifndef FILTER_USER_REDIRECT_ONLY

#define MAX_FILTER_INSTANCE_NAME_LENGTH     256
#define MAX_FILTER_CONFIG_KEYWORD_LENGTH    256
typedef struct _FILTER_DRIVER_ALL_STAT
{
    ULONG          AttachCount;
    ULONG          DetachCount;
    ULONG          ExternalRequestFailedCount;
    ULONG          ExternalRequestSuccessCount;
    ULONG          InternalRequestFailedCount;
} FILTER_DRIVER_ALL_STAT, * PFILTER_DRIVER_ALL_STAT;


typedef struct _FILTER_SET_OID
{
    WCHAR           InstanceName[MAX_FILTER_INSTANCE_NAME_LENGTH];
    ULONG           InstanceNameLength;
    NDIS_OID        Oid;
    NDIS_STATUS     Status;
    UCHAR           Data[sizeof(ULONG)];

}FILTER_SET_OID, *PFILTER_SET_OID;

typedef struct _FILTER_QUERY_OID
{
    WCHAR           InstanceName[MAX_FILTER_INSTANCE_NAME_LENGTH];
    ULONG           InstanceNameLength;
    NDIS_OID        Oid;
    NDIS_STATUS     Status;
    UCHAR           Data[sizeof(ULONG)];

}FILTER_QUERY_OID, *PFILTER_QUERY_OID;

typedef struct _FILTER_READ_CONFIG
{
    __field_bcount_part(MAX_FILTER_INSTANCE_NAME_LENGTH,InstanceNameLength) 
    WCHAR                   InstanceName[MAX_FILTER_INSTANCE_NAME_LENGTH];
    ULONG                   InstanceNameLength;
    __field_bcount_part(MAX_FILTER_CONFIG_KEYWORD_LENGTH,KeywordLength) 
    WCHAR                   Keyword[MAX_FILTER_CONFIG_KEYWORD_LENGTH];
    ULONG                   KeywordLength;
    NDIS_PARAMETER_TYPE     ParameterType;
    NDIS_STATUS             Status;
    UCHAR                   Data[sizeof(ULONG)];
}FILTER_READ_CONFIG, *PFILTER_READ_CONFIG;

typedef struct _FILTER_WRITE_CONFIG
{
    __field_bcount_part(MAX_FILTER_INSTANCE_NAME_LENGTH,InstanceNameLength) 
    WCHAR                   InstanceName[MAX_FILTER_INSTANCE_NAME_LENGTH];
    ULONG                   InstanceNameLength;
    __field_bcount_part(MAX_FILTER_CONFIG_KEYWORD_LENGTH,KeywordLength) 
    WCHAR                   Keyword[MAX_FILTER_CONFIG_KEYWORD_LENGTH];
    ULONG                   KeywordLength;
    NDIS_PARAMETER_TYPE     ParameterType;
    NDIS_STATUS             Status;
    UCHAR                   Data[sizeof(ULONG)];
}FILTER_WRITE_CONFIG, *PFILTER_WRITE_CONFIG;

#endif // FILTER_USER_REDIRECT_ONLY

//
// IP and Port redirection definitions (shared between kernel and user mode)
//
#define REDIRECT_AF_IPV4            4
#define REDIRECT_AF_IPV6            6

#define REDIRECT_PROTO_ANY          0
#define REDIRECT_PROTO_TCP          6
#define REDIRECT_PROTO_UDP          17

#define REDIRECT_FLAG_REWRITE_MAC       0x0001
#define REDIRECT_FLAG_LOCAL_LOOPBACK    0x0002

#define MAX_REDIRECT_RULES          64

typedef union _REDIRECT_IP_ADDR
{
    UCHAR               V4[4];
    UCHAR               V6[16];
} REDIRECT_IP_ADDR, *PREDIRECT_IP_ADDR;

typedef struct _REDIRECT_RULE
{
    ULONG               RuleId;         // 0 = auto-assign, non-zero = add or update by ID
    UCHAR               AddressFamily;  // REDIRECT_AF_IPV4 or REDIRECT_AF_IPV6
    UCHAR               Protocol;       // REDIRECT_PROTO_ANY / TCP / UDP
    USHORT              Flags;          // REDIRECT_FLAG_*
    REDIRECT_IP_ADDR    OrigIp;         // Original destination IP (network byte order)
    USHORT              OrigPort;       // Original destination port (network byte order, 0 = any)
    USHORT              NewPort;        // Target destination port (network byte order, 0 = keep original)
    REDIRECT_IP_ADDR    NewIp;          // Target destination IP (network byte order)
    UCHAR               NewDstMac[6];   // Target next-hop MAC when REDIRECT_FLAG_REWRITE_MAC is set
    UCHAR               Reserved[2];
} REDIRECT_RULE, *PREDIRECT_RULE;

typedef struct _REDIRECT_DEL_RULE
{
    ULONG               RuleId;
} REDIRECT_DEL_RULE, *PREDIRECT_DEL_RULE;

//
// DNS spoofing definitions (shared between kernel and user mode)
//
#define DNS_SPOOF_FLAG_HAS_IPV4         0x0001
#define DNS_SPOOF_FLAG_HAS_IPV6         0x0002
#define DNS_SPOOF_FLAG_WILDCARD         0x0004

#define DNS_SPOOF_MAX_DOMAIN_LEN        256
#define MAX_DNS_SPOOF_RULES             64
#define DNS_SPOOF_DEFAULT_TTL           30

typedef struct _DNS_SPOOF_RULE
{
    ULONG               RuleId;         // 0 = auto-assign, non-zero = add or update by ID
    USHORT              Flags;          // DNS_SPOOF_FLAG_*
    USHORT              Reserved;
    ULONG               Ttl;            // Answer TTL in seconds (0 = default 30s)
    UCHAR               FakeIpv4[4];    // Forged IPv4 address (network byte order)
    UCHAR               FakeIpv6[16];   // Forged IPv6 address (network byte order)
    CHAR                Domain[DNS_SPOOF_MAX_DOMAIN_LEN]; // Lowercase ASCII domain (e.g. "baidu.com" or "*.baidu.com")
} DNS_SPOOF_RULE, *PDNS_SPOOF_RULE;

typedef struct _DNS_SPOOF_DEL_RULE
{
    ULONG               RuleId;
} DNS_SPOOF_DEL_RULE, *PDNS_SPOOF_DEL_RULE;

#endif //__FILTERUSER_H__


