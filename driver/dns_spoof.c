/*++

Module Name:

    dns_spoof.c

Abstract:

    DNS spoofing engine for NDIS 6.0 LWF.
    Supports:
    - Exact domain match ("baidu.com") and wildcard suffix match ("*.baidu.com")
    - IPv4 (A) and IPv6 (AAAA) forged answers, plus NODATA responses when a
      matched domain only configures the other address family
    - Zero-race outbound interception with async local receive injection

--*/

#include "precomp.h"

#define __FILENUMBER    'DNSS'

#define DNS_ETH_ADDR_LEN            6
#define DNS_ETH_TYPE_IPV4           0x0800
#define DNS_ETH_TYPE_IPV6           0x86DD
#define DNS_ETH_TYPE_VLAN           0x8100
#define DNS_ETH_TYPE_QINQ           0x88A8

#define DNS_PROTO_UDP               17
#define DNS_PORT_53                 53

#define DNS_TYPE_A                  1
#define DNS_TYPE_AAAA               28
#define DNS_CLASS_IN                1

#define DNS_HEADER_LEN              12
#define DNS_MAX_VLAN_DEPTH          2
#define DNS_PEEK_LEN                96
#define DNS_MAX_QUERY_FRAME_LEN     1024
#define DNS_MAX_WIRE_DOMAIN_LEN     253

#include <pshpack1.h>

typedef struct _DNS_ETH_HDR
{
    UCHAR       DstMac[DNS_ETH_ADDR_LEN];
    UCHAR       SrcMac[DNS_ETH_ADDR_LEN];
    USHORT      EtherType;
} DNS_ETH_HDR, *PDNS_ETH_HDR;

typedef struct _DNS_VLAN_HDR
{
    USHORT      Tci;
    USHORT      EtherType;
} DNS_VLAN_HDR, *PDNS_VLAN_HDR;

typedef struct _DNS_IPV4_HDR
{
    UCHAR       VerIhl;
    UCHAR       Tos;
    USHORT      TotalLength;
    USHORT      Identification;
    USHORT      FlagsFragOffset;
    UCHAR       Ttl;
    UCHAR       Protocol;
    USHORT      HeaderChecksum;
    UCHAR       SrcAddr[4];
    UCHAR       DstAddr[4];
} DNS_IPV4_HDR, *PDNS_IPV4_HDR;

typedef struct _DNS_IPV6_HDR
{
    UCHAR       VerTcHi;
    UCHAR       TcLoFlowHi;
    USHORT      FlowLo;
    USHORT      PayloadLength;
    UCHAR       NextHeader;
    UCHAR       HopLimit;
    UCHAR       SrcAddr[16];
    UCHAR       DstAddr[16];
} DNS_IPV6_HDR, *PDNS_IPV6_HDR;

typedef struct _DNS_UDP_HDR
{
    USHORT      SrcPort;
    USHORT      DstPort;
    USHORT      Length;
    USHORT      Checksum;
} DNS_UDP_HDR, *PDNS_UDP_HDR;

typedef struct _DNS_WIRE_HDR
{
    USHORT      TransactionId;
    USHORT      Flags;
    USHORT      QuestionCount;
    USHORT      AnswerCount;
    USHORT      AuthorityCount;
    USHORT      AdditionalCount;
} DNS_WIRE_HDR, *PDNS_WIRE_HDR;

#include <poppack.h>

typedef struct _DNS_PARSED_FRAME
{
    UCHAR       AddressFamily;      // REDIRECT_AF_IPV4 or REDIRECT_AF_IPV6
    ULONG       IpOffset;
    ULONG       IpHeaderLen;
    ULONG       UdpOffset;
    ULONG       UdpLen;
    USHORT      SrcPort;            // Network byte order
    USHORT      DstPort;            // Network byte order
    USHORT      Ipv4Id;             // Network byte order
    UCHAR       SrcIp[16];
    UCHAR       DstIp[16];
} DNS_PARSED_FRAME, *PDNS_PARSED_FRAME;

//
// Global rule table
//
static BOOLEAN          gDnsSpoofInitialized = FALSE;
static NDIS_RW_LOCK     gDnsRuleLock;
static DNS_SPOOF_RULE   gDnsRules[MAX_DNS_SPOOF_RULES];
static ULONG            gDnsRuleCount = 0;
static ULONG            gDnsNextRuleId = 1;

//
// Checksum helpers (big-endian byte accumulation)
//
static
ULONG
DnsSumBytesBe(
    IN const UCHAR *Buf,
    IN ULONG        Len,
    IN ULONG        InitialSum
    )
{
    ULONG   Sum = InitialSum;
    ULONG   i = 0;

    while (i + 1 < Len)
    {
        Sum += (((ULONG)Buf[i] << 8) | (ULONG)Buf[i + 1]);
        i += 2;
    }

    if (i < Len)
    {
        Sum += ((ULONG)Buf[i] << 8);
    }

    return Sum;
}

static
USHORT
DnsFoldSum(
    IN ULONG    Sum
    )
{
    while ((Sum >> 16) != 0)
    {
        Sum = (Sum & 0xFFFFUL) + (Sum >> 16);
    }

    return (USHORT)Sum;
}

static
VOID
DnsCalcIpv4HeaderChecksum(
    IN OUT PDNS_IPV4_HDR    Ip4
    )
{
    ULONG   Sum;
    USHORT  Folded;

    Ip4->HeaderChecksum = 0;
    Sum = DnsSumBytesBe((const UCHAR *)Ip4, sizeof(DNS_IPV4_HDR), 0);
    Folded = (USHORT)(~DnsFoldSum(Sum));
    Ip4->HeaderChecksum = RtlUshortByteSwap(Folded);
}

static
USHORT
DnsCalcUdpChecksum(
    IN UCHAR        AddressFamily,
    IN const UCHAR *SrcIp,
    IN const UCHAR *DstIp,
    IN const UCHAR *UdpSegment,
    IN ULONG        UdpLen
    )
{
    ULONG   Sum = 0;
    USHORT  Folded;

    if (AddressFamily == REDIRECT_AF_IPV4)
    {
        Sum = DnsSumBytesBe(SrcIp, 4, Sum);
        Sum = DnsSumBytesBe(DstIp, 4, Sum);
        Sum += (ULONG)DNS_PROTO_UDP;
        Sum += (UdpLen & 0xFFFFUL);
    }
    else
    {
        Sum = DnsSumBytesBe(SrcIp, 16, Sum);
        Sum = DnsSumBytesBe(DstIp, 16, Sum);
        Sum += ((UdpLen >> 16) & 0xFFFFUL);
        Sum += (UdpLen & 0xFFFFUL);
        Sum += (ULONG)DNS_PROTO_UDP;
    }

    Sum = DnsSumBytesBe(UdpSegment, UdpLen, Sum);
    Folded = (USHORT)(~DnsFoldSum(Sum));
    if (Folded == 0)
    {
        Folded = 0xFFFF;
    }
    return RtlUshortByteSwap(Folded);
}

//
// Domain normalization & matching helpers
//
static
CHAR
DnsToLowerAscii(
    IN CHAR c
    )
{
    if (c >= 'A' && c <= 'Z')
    {
        return (CHAR)(c + ('a' - 'A'));
    }
    return c;
}

static
BOOLEAN
DnsIsValidLabelChar(
    IN CHAR c
    )
{
    if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_')
    {
        return TRUE;
    }
    return FALSE;
}

static
BOOLEAN
DnsNormalizeDomain(
    IN  const CHAR *Input,
    IN  USHORT      InputFlags,
    OUT CHAR        OutDomain[DNS_SPOOF_MAX_DOMAIN_LEN],
    OUT PUSHORT     OutFlags
    )
{
    ULONG   Len = 0;
    ULONG   Start = 0;
    ULONG   End = 0;
    ULONG   OutPos = 0;
    ULONG   LabelLen = 0;
    BOOLEAN IsWildcard = FALSE;
    ULONG   i;

    NdisZeroMemory(OutDomain, DNS_SPOOF_MAX_DOMAIN_LEN);

    while (Len < DNS_SPOOF_MAX_DOMAIN_LEN && Input[Len] != '\0')
    {
        Len++;
    }
    if (Len == 0 || Len >= DNS_SPOOF_MAX_DOMAIN_LEN)
    {
        return FALSE;
    }

    // Trim leading/trailing spaces and trailing dots
    while (Start < Len && (Input[Start] == ' ' || Input[Start] == '\t'))
    {
        Start++;
    }
    End = Len;
    while (End > Start && (Input[End - 1] == ' ' || Input[End - 1] == '\t' || Input[End - 1] == '.'))
    {
        End--;
    }

    if (End <= Start)
    {
        return FALSE;
    }

    if ((End - Start) >= 2 && Input[Start] == '*' && Input[Start + 1] == '.')
    {
        IsWildcard = TRUE;
        Start += 2;
    }
    else if ((InputFlags & DNS_SPOOF_FLAG_WILDCARD) != 0)
    {
        IsWildcard = TRUE;
    }

    if (End <= Start)
    {
        return FALSE;
    }

    if (IsWildcard)
    {
        OutDomain[OutPos++] = '*';
        OutDomain[OutPos++] = '.';
    }

    for (i = Start; i < End; i++)
    {
        CHAR c = DnsToLowerAscii(Input[i]);
        if (OutPos >= DNS_MAX_WIRE_DOMAIN_LEN)
        {
            return FALSE;
        }
        if (c == '.')
        {
            if (LabelLen == 0)
            {
                return FALSE;
            }
            LabelLen = 0;
            OutDomain[OutPos++] = '.';
        }
        else if (DnsIsValidLabelChar(c))
        {
            LabelLen++;
            if (LabelLen > 63)
            {
                return FALSE;
            }
            OutDomain[OutPos++] = c;
        }
        else
        {
            return FALSE;
        }
    }

    if (LabelLen == 0)
    {
        return FALSE;
    }

    OutDomain[OutPos] = '\0';
    *OutFlags = (USHORT)(InputFlags & (DNS_SPOOF_FLAG_HAS_IPV4 | DNS_SPOOF_FLAG_HAS_IPV6));
    if (IsWildcard)
    {
        *OutFlags |= DNS_SPOOF_FLAG_WILDCARD;
    }
    return TRUE;
}

static
ULONG
DnsStrLenBounded(
    IN const CHAR  *Str,
    IN ULONG        MaxLen
    )
{
    ULONG n = 0;
    while (n < MaxLen && Str[n] != '\0')
    {
        n++;
    }
    return n;
}

static
BOOLEAN
DnsStrEqual(
    IN const CHAR  *A,
    IN ULONG        LenA,
    IN const CHAR  *B,
    IN ULONG        LenB
    )
{
    if (LenA != LenB)
    {
        return FALSE;
    }
    if (LenA == 0)
    {
        return TRUE;
    }
    return (RtlCompareMemory(A, B, LenA) == LenA) ? TRUE : FALSE;
}

static
BOOLEAN
DnsMatchRule(
    IN  const CHAR      *QueryDomain,
    IN  ULONG            QueryLen,
    OUT PDNS_SPOOF_RULE  OutRule
    )
{
    LOCK_STATE  LockState;
    ULONG       i;
    BOOLEAN     FoundWildcard = FALSE;
    ULONG       BestWildcardSuffixLen = 0;
    ULONG       BestWildcardIdx = 0;

    NdisAcquireReadWriteLock(&gDnsRuleLock, FALSE, &LockState);

    for (i = 0; i < gDnsRuleCount; i++)
    {
        const DNS_SPOOF_RULE *Rule = &gDnsRules[i];
        ULONG                 RuleLen = DnsStrLenBounded(Rule->Domain, DNS_SPOOF_MAX_DOMAIN_LEN);

        if ((Rule->Flags & DNS_SPOOF_FLAG_WILDCARD) == 0)
        {
            if (DnsStrEqual(QueryDomain, QueryLen, Rule->Domain, RuleLen))
            {
                *OutRule = *Rule;
                NdisReleaseReadWriteLock(&gDnsRuleLock, &LockState);
                return TRUE;
            }
        }
        else if (RuleLen > 2 && Rule->Domain[0] == '*' && Rule->Domain[1] == '.')
        {
            const CHAR *Suffix = Rule->Domain + 2;
            ULONG       SuffixLen = RuleLen - 2;

            // Wildcard "*.baidu.com" matches any subdomain ending with ".baidu.com"
            if (QueryLen > SuffixLen &&
                QueryDomain[QueryLen - SuffixLen - 1] == '.' &&
                DnsStrEqual(QueryDomain + (QueryLen - SuffixLen), SuffixLen, Suffix, SuffixLen))
            {
                if (!FoundWildcard || SuffixLen > BestWildcardSuffixLen)
                {
                    FoundWildcard = TRUE;
                    BestWildcardSuffixLen = SuffixLen;
                    BestWildcardIdx = i;
                }
            }
        }
    }

    if (FoundWildcard)
    {
        *OutRule = gDnsRules[BestWildcardIdx];
        NdisReleaseReadWriteLock(&gDnsRuleLock, &LockState);
        return TRUE;
    }

    NdisReleaseReadWriteLock(&gDnsRuleLock, &LockState);
    return FALSE;
}

//
// Packet parsing helpers
//
static
BOOLEAN
DnsCopyNbToBuffer(
    IN  PNET_BUFFER Nb,
    OUT PUCHAR      DstBuf,
    IN  ULONG       DataLen
    )
{
    PMDL    Mdl = NET_BUFFER_CURRENT_MDL(Nb);
    ULONG   MdlOffset = NET_BUFFER_CURRENT_MDL_OFFSET(Nb);
    ULONG   Remaining = DataLen;
    ULONG   DstPos = 0;

    while (Remaining > 0 && Mdl != NULL)
    {
        PUCHAR  SrcVa = (PUCHAR)MmGetSystemAddressForMdlSafe(Mdl, NormalPagePriority);
        ULONG   MdlLen = MmGetMdlByteCount(Mdl);
        ULONG   Avail;
        ULONG   ToCopy;

        if (SrcVa == NULL)
        {
            return FALSE;
        }
        if (MdlOffset >= MdlLen)
        {
            MdlOffset -= MdlLen;
            Mdl = Mdl->Next;
            continue;
        }

        Avail = MdlLen - MdlOffset;
        ToCopy = (Remaining < Avail) ? Remaining : Avail;
        NdisMoveMemory(DstBuf + DstPos, SrcVa + MdlOffset, ToCopy);
        DstPos += ToCopy;
        Remaining -= ToCopy;
        MdlOffset = 0;
        Mdl = Mdl->Next;
    }

    return (Remaining == 0) ? TRUE : FALSE;
}

static
BOOLEAN
DnsParseUdp53Headers(
    IN  const UCHAR        *Buf,
    IN  ULONG               BufLen,
    OUT PDNS_PARSED_FRAME   OutInfo
    )
{
    ULONG           Offset = 0;
    USHORT          EtherType;
    ULONG           VlanDepth = 0;
    PDNS_UDP_HDR    Udp;
    USHORT          UdpLenHost;

    NdisZeroMemory(OutInfo, sizeof(DNS_PARSED_FRAME));

    if (BufLen < sizeof(DNS_ETH_HDR))
    {
        return FALSE;
    }

    EtherType = RtlUshortByteSwap(((const DNS_ETH_HDR *)Buf)->EtherType);
    Offset = sizeof(DNS_ETH_HDR);

    while ((EtherType == DNS_ETH_TYPE_VLAN || EtherType == DNS_ETH_TYPE_QINQ) &&
           VlanDepth < DNS_MAX_VLAN_DEPTH)
    {
        if (Offset + sizeof(DNS_VLAN_HDR) > BufLen)
        {
            return FALSE;
        }
        EtherType = RtlUshortByteSwap(((const DNS_VLAN_HDR *)(Buf + Offset))->EtherType);
        Offset += sizeof(DNS_VLAN_HDR);
        VlanDepth++;
    }

    OutInfo->IpOffset = Offset;

    if (EtherType == DNS_ETH_TYPE_IPV4)
    {
        const DNS_IPV4_HDR *Ip4;
        ULONG               Ihl;
        USHORT              FragFlags;

        if (Offset + sizeof(DNS_IPV4_HDR) > BufLen)
        {
            return FALSE;
        }
        Ip4 = (const DNS_IPV4_HDR *)(Buf + Offset);
        if ((Ip4->VerIhl >> 4) != 4)
        {
            return FALSE;
        }
        Ihl = (ULONG)(Ip4->VerIhl & 0x0F) * 4;
        if (Ihl < sizeof(DNS_IPV4_HDR) || Offset + Ihl > BufLen)
        {
            return FALSE;
        }
        FragFlags = RtlUshortByteSwap(Ip4->FlagsFragOffset);
        if ((FragFlags & 0x3FFF) != 0)
        {
            // Fragmented IPv4 packet: passthrough
            return FALSE;
        }
        if (Ip4->Protocol != DNS_PROTO_UDP)
        {
            return FALSE;
        }

        OutInfo->AddressFamily = REDIRECT_AF_IPV4;
        OutInfo->IpHeaderLen = Ihl;
        OutInfo->UdpOffset = Offset + Ihl;
        OutInfo->Ipv4Id = Ip4->Identification;
        NdisMoveMemory(OutInfo->SrcIp, Ip4->SrcAddr, 4);
        NdisMoveMemory(OutInfo->DstIp, Ip4->DstAddr, 4);
    }
    else if (EtherType == DNS_ETH_TYPE_IPV6)
    {
        const DNS_IPV6_HDR *Ip6;

        if (Offset + sizeof(DNS_IPV6_HDR) > BufLen)
        {
            return FALSE;
        }
        Ip6 = (const DNS_IPV6_HDR *)(Buf + Offset);
        if ((Ip6->VerTcHi >> 4) != 6)
        {
            return FALSE;
        }
        if (Ip6->NextHeader != DNS_PROTO_UDP)
        {
            return FALSE;
        }

        OutInfo->AddressFamily = REDIRECT_AF_IPV6;
        OutInfo->IpHeaderLen = sizeof(DNS_IPV6_HDR);
        OutInfo->UdpOffset = Offset + sizeof(DNS_IPV6_HDR);
        NdisMoveMemory(OutInfo->SrcIp, Ip6->SrcAddr, 16);
        NdisMoveMemory(OutInfo->DstIp, Ip6->DstAddr, 16);
    }
    else
    {
        return FALSE;
    }

    if (OutInfo->UdpOffset + sizeof(DNS_UDP_HDR) > BufLen)
    {
        return FALSE;
    }

    Udp = (PDNS_UDP_HDR)(Buf + OutInfo->UdpOffset);
    if (RtlUshortByteSwap(Udp->DstPort) != DNS_PORT_53)
    {
        return FALSE;
    }

    UdpLenHost = RtlUshortByteSwap(Udp->Length);
    if (UdpLenHost < sizeof(DNS_UDP_HDR) + DNS_HEADER_LEN + 5)
    {
        return FALSE;
    }

    OutInfo->SrcPort = Udp->SrcPort;
    OutInfo->DstPort = Udp->DstPort;
    OutInfo->UdpLen = (ULONG)UdpLenHost;
    return TRUE;
}

static
BOOLEAN
DnsParseStandardQuery(
    IN  const UCHAR *DnsBuf,
    IN  ULONG        DnsLen,
    OUT CHAR         OutDomain[DNS_SPOOF_MAX_DOMAIN_LEN],
    OUT PULONG       OutDomainLen,
    OUT PUSHORT      OutQType,
    OUT PULONG       OutQuestionSectionLen,
    OUT PUSHORT      OutOrigFlagsHost
    )
{
    const DNS_WIRE_HDR *Hdr;
    USHORT              Flags;
    USHORT              QdCount;
    USHORT              AnCount;
    ULONG               Pos = DNS_HEADER_LEN;
    ULONG               DomainPos = 0;
    USHORT              QType;
    USHORT              QClass;

    if (DnsLen < DNS_HEADER_LEN + 5)
    {
        return FALSE;
    }

    Hdr = (const DNS_WIRE_HDR *)DnsBuf;
    Flags = RtlUshortByteSwap(Hdr->Flags);
    QdCount = RtlUshortByteSwap(Hdr->QuestionCount);
    AnCount = RtlUshortByteSwap(Hdr->AnswerCount);

    // Must be standard query (QR=0, OPCODE=0), single question, 0 answers
    if ((Flags & 0x8000) != 0 || (Flags & 0x7800) != 0)
    {
        return FALSE;
    }
    if (QdCount != 1 || AnCount != 0)
    {
        return FALSE;
    }

    // Parse QNAME labels safely (no compression pointers allowed in query QNAME)
    for (;;)
    {
        UCHAR LabelLen;
        ULONG i;

        if (Pos >= DnsLen)
        {
            return FALSE;
        }

        LabelLen = DnsBuf[Pos++];
        if (LabelLen == 0)
        {
            break;
        }
        if ((LabelLen & 0xC0) != 0 || LabelLen > 63)
        {
            return FALSE;
        }
        if (Pos + LabelLen > DnsLen)
        {
            return FALSE;
        }

        if (DomainPos > 0)
        {
            if (DomainPos >= DNS_MAX_WIRE_DOMAIN_LEN)
            {
                return FALSE;
            }
            OutDomain[DomainPos++] = '.';
        }

        if (DomainPos + LabelLen > DNS_MAX_WIRE_DOMAIN_LEN)
        {
            return FALSE;
        }

        for (i = 0; i < LabelLen; i++)
        {
            OutDomain[DomainPos++] = DnsToLowerAscii((CHAR)DnsBuf[Pos++]);
        }
    }

    if (DomainPos == 0 || Pos + 4 > DnsLen)
    {
        return FALSE;
    }

    OutDomain[DomainPos] = '\0';

    QType = (USHORT)(((USHORT)DnsBuf[Pos] << 8) | (USHORT)DnsBuf[Pos + 1]);
    QClass = (USHORT)(((USHORT)DnsBuf[Pos + 2] << 8) | (USHORT)DnsBuf[Pos + 3]);
    Pos += 4;

    if (QClass != DNS_CLASS_IN)
    {
        return FALSE;
    }
    if (QType != DNS_TYPE_A && QType != DNS_TYPE_AAAA)
    {
        return FALSE;
    }

    *OutDomainLen = DomainPos;
    *OutQType = QType;
    *OutQuestionSectionLen = Pos - DNS_HEADER_LEN;
    *OutOrigFlagsHost = Flags;
    return TRUE;
}

//
// Lifecycle APIs
//
VOID
DnsSpoofGlobalInit(
    VOID
    )
{
    if (!gDnsSpoofInitialized)
    {
        NdisInitializeReadWriteLock(&gDnsRuleLock);
        NdisZeroMemory(gDnsRules, sizeof(gDnsRules));
        gDnsRuleCount = 0;
        gDnsNextRuleId = 1;
        gDnsSpoofInitialized = TRUE;
    }
}

VOID
DnsSpoofGlobalCleanup(
    VOID
    )
{
    if (gDnsSpoofInitialized)
    {
        DnsSpoofClearRules();
        gDnsSpoofInitialized = FALSE;
    }
}

//
// Control-plane APIs
//
NTSTATUS
DnsSpoofAddRule(
    IN OUT PDNS_SPOOF_RULE  Rule
    )
{
    LOCK_STATE      LockState;
    DNS_SPOOF_RULE  Normalized;
    USHORT          NormFlags = 0;
    ULONG           i;
    NTSTATUS        Status = STATUS_SUCCESS;

    if (Rule == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if ((Rule->Flags & (DNS_SPOOF_FLAG_HAS_IPV4 | DNS_SPOOF_FLAG_HAS_IPV6)) == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    NdisZeroMemory(&Normalized, sizeof(Normalized));
    if (!DnsNormalizeDomain(Rule->Domain, Rule->Flags, Normalized.Domain, &NormFlags))
    {
        return STATUS_INVALID_PARAMETER;
    }

    Normalized.RuleId = Rule->RuleId;
    Normalized.Flags = NormFlags;
    Normalized.Ttl = (Rule->Ttl != 0) ? Rule->Ttl : DNS_SPOOF_DEFAULT_TTL;

    if ((NormFlags & DNS_SPOOF_FLAG_HAS_IPV4) != 0)
    {
        NdisMoveMemory(Normalized.FakeIpv4, Rule->FakeIpv4, 4);
    }
    if ((NormFlags & DNS_SPOOF_FLAG_HAS_IPV6) != 0)
    {
        NdisMoveMemory(Normalized.FakeIpv6, Rule->FakeIpv6, 16);
    }

    NdisAcquireReadWriteLock(&gDnsRuleLock, TRUE, &LockState);

    if (Normalized.RuleId == 0)
    {
        if (gDnsNextRuleId == 0)
        {
            gDnsNextRuleId = 1;
        }
        Normalized.RuleId = gDnsNextRuleId++;
    }
    else
    {
        for (i = 0; i < gDnsRuleCount; i++)
        {
            if (gDnsRules[i].RuleId == Normalized.RuleId)
            {
                gDnsRules[i] = Normalized;
                NdisReleaseReadWriteLock(&gDnsRuleLock, &LockState);
                *Rule = Normalized;
                return STATUS_SUCCESS;
            }
        }
        if (Normalized.RuleId >= gDnsNextRuleId)
        {
            gDnsNextRuleId = Normalized.RuleId + 1;
        }
    }

    if (gDnsRuleCount >= MAX_DNS_SPOOF_RULES)
    {
        Status = STATUS_INSUFFICIENT_RESOURCES;
    }
    else
    {
        gDnsRules[gDnsRuleCount++] = Normalized;
        *Rule = Normalized;
    }

    NdisReleaseReadWriteLock(&gDnsRuleLock, &LockState);
    return Status;
}

NTSTATUS
DnsSpoofDeleteRule(
    IN ULONG    RuleId
    )
{
    LOCK_STATE  LockState;
    ULONG       i;
    BOOLEAN     Found = FALSE;

    if (RuleId == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    NdisAcquireReadWriteLock(&gDnsRuleLock, TRUE, &LockState);

    for (i = 0; i < gDnsRuleCount; i++)
    {
        if (gDnsRules[i].RuleId == RuleId)
        {
            if (i + 1 < gDnsRuleCount)
            {
                NdisMoveMemory(
                    &gDnsRules[i],
                    &gDnsRules[i + 1],
                    (gDnsRuleCount - i - 1) * sizeof(DNS_SPOOF_RULE));
            }
            gDnsRuleCount--;
            Found = TRUE;
            break;
        }
    }

    NdisReleaseReadWriteLock(&gDnsRuleLock, &LockState);
    return Found ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

VOID
DnsSpoofClearRules(
    VOID
    )
{
    LOCK_STATE  LockState;

    NdisAcquireReadWriteLock(&gDnsRuleLock, TRUE, &LockState);
    gDnsRuleCount = 0;
    NdisReleaseReadWriteLock(&gDnsRuleLock, &LockState);
}

NTSTATUS
DnsSpoofListRules(
    OUT PDNS_SPOOF_RULE Buffer,
    IN  ULONG           BufferLength,
    OUT PULONG          BytesRequired
    )
{
    LOCK_STATE  LockState;
    ULONG       Needed;
    NTSTATUS    Status;

    NdisAcquireReadWriteLock(&gDnsRuleLock, FALSE, &LockState);

    Needed = gDnsRuleCount * sizeof(DNS_SPOOF_RULE);
    *BytesRequired = Needed;

    if (Needed == 0)
    {
        Status = STATUS_SUCCESS;
    }
    else if (Buffer == NULL || BufferLength < Needed)
    {
        Status = STATUS_BUFFER_TOO_SMALL;
    }
    else
    {
        NdisMoveMemory(Buffer, gDnsRules, Needed);
        Status = STATUS_SUCCESS;
    }

    NdisReleaseReadWriteLock(&gDnsRuleLock, &LockState);
    return Status;
}

//
// Data-plane interception & forged response injection
//
BOOLEAN
DnsSpoofProcessSendNbl(
    IN PMS_FILTER       pFilter,
    IN PNET_BUFFER_LIST OrigNbl,
    IN BOOLEAN          DispatchLevel
    )
{
    PNET_BUFFER         Nb;
    ULONG               TotalLen;
    UCHAR               PeekBuf[DNS_PEEK_LEN];
    ULONG               PeekLen;
    const UCHAR        *PeekPtr;
    DNS_PARSED_FRAME    Frame;
    PUCHAR              QueryBuf = NULL;
    PUCHAR              RespBuf = NULL;
    CHAR                QueryDomain[DNS_SPOOF_MAX_DOMAIN_LEN];
    ULONG               QueryDomainLen = 0;
    USHORT              QType = 0;
    ULONG               QSectionLen = 0;
    USHORT              OrigDnsFlags = 0;
    DNS_SPOOF_RULE      Rule;
    BOOLEAN             HasAnswer = FALSE;
    USHORT              AnswerRdLen = 0;
    ULONG               AnswerBytes = 0;
    ULONG               RespIpHdrLen;
    ULONG               RespDnsLen;
    ULONG               RespUdpLen;
    ULONG               RespTotalLen;
    BOOLEAN             Injected = FALSE;

    if (!gDnsSpoofInitialized || gDnsRuleCount == 0 || pFilter == NULL || OrigNbl == NULL)
    {
        return FALSE;
    }

    Nb = NET_BUFFER_LIST_FIRST_NB(OrigNbl);
    if (Nb == NULL || NET_BUFFER_NEXT_NB(Nb) != NULL)
    {
        return FALSE;
    }

    TotalLen = NET_BUFFER_DATA_LENGTH(Nb);
    if (TotalLen < (sizeof(DNS_ETH_HDR) + sizeof(DNS_IPV4_HDR) + sizeof(DNS_UDP_HDR) + DNS_HEADER_LEN + 5) ||
        TotalLen > DNS_MAX_QUERY_FRAME_LEN)
    {
        return FALSE;
    }

    // Fast path: peek L2/L3/UDP headers on stack to reject non-UDP/53 packets without pool alloc
    PeekLen = (TotalLen < DNS_PEEK_LEN) ? TotalLen : DNS_PEEK_LEN;
    PeekPtr = (const UCHAR *)NdisGetDataBuffer(Nb, PeekLen, PeekBuf, 1, 0);
    if (PeekPtr == NULL)
    {
        return FALSE;
    }

    if (!DnsParseUdp53Headers(PeekPtr, PeekLen, &Frame))
    {
        return FALSE;
    }

    if (Frame.UdpOffset + Frame.UdpLen > TotalLen)
    {
        return FALSE;
    }

    // Copy full query frame into contiguous buffer
    QueryBuf = (PUCHAR)NdisAllocateMemoryWithTagPriority(
                           pFilter->FilterHandle,
                           TotalLen,
                           FILTER_ALLOC_TAG,
                           NormalPoolPriority);
    if (QueryBuf == NULL)
    {
        return FALSE;
    }

    if (!DnsCopyNbToBuffer(Nb, QueryBuf, TotalLen))
    {
        goto Exit;
    }

    if (!DnsParseStandardQuery(
             QueryBuf + Frame.UdpOffset + sizeof(DNS_UDP_HDR),
             Frame.UdpLen - sizeof(DNS_UDP_HDR),
             QueryDomain,
             &QueryDomainLen,
             &QType,
             &QSectionLen,
             &OrigDnsFlags))
    {
        goto Exit;
    }

    if (!DnsMatchRule(QueryDomain, QueryDomainLen, &Rule))
    {
        goto Exit;
    }

    // Determine forged answer vs NODATA
    if (QType == DNS_TYPE_A && (Rule.Flags & DNS_SPOOF_FLAG_HAS_IPV4) != 0)
    {
        HasAnswer = TRUE;
        AnswerRdLen = 4;
        AnswerBytes = 12 + 4;
    }
    else if (QType == DNS_TYPE_AAAA && (Rule.Flags & DNS_SPOOF_FLAG_HAS_IPV6) != 0)
    {
        HasAnswer = TRUE;
        AnswerRdLen = 16;
        AnswerBytes = 12 + 16;
    }
    else
    {
        // Matched domain only configures the other address family:
        // return clean NODATA (RCODE=0, ANCOUNT=0) so OS falls back cleanly.
        HasAnswer = FALSE;
        AnswerRdLen = 0;
        AnswerBytes = 0;
    }

    RespIpHdrLen = (Frame.AddressFamily == REDIRECT_AF_IPV4)
                       ? sizeof(DNS_IPV4_HDR)
                       : sizeof(DNS_IPV6_HDR);
    RespDnsLen = DNS_HEADER_LEN + QSectionLen + AnswerBytes;
    RespUdpLen = sizeof(DNS_UDP_HDR) + RespDnsLen;
    RespTotalLen = Frame.IpOffset + RespIpHdrLen + RespUdpLen;

    if (RespTotalLen > 1500)
    {
        goto Exit;
    }

    RespBuf = (PUCHAR)NdisAllocateMemoryWithTagPriority(
                          pFilter->FilterHandle,
                          RespTotalLen,
                          FILTER_ALLOC_TAG,
                          NormalPoolPriority);
    if (RespBuf == NULL)
    {
        goto Exit;
    }

    NdisZeroMemory(RespBuf, RespTotalLen);

    // 1. L2 header (preserve Ethernet + VLAN tags, swap DstMac <-> SrcMac)
    NdisMoveMemory(RespBuf, QueryBuf, Frame.IpOffset);
    {
        PDNS_ETH_HDR    RespEth = (PDNS_ETH_HDR)RespBuf;
        const DNS_ETH_HDR *OrigEth = (const DNS_ETH_HDR *)QueryBuf;
        NdisMoveMemory(RespEth->DstMac, OrigEth->SrcMac, DNS_ETH_ADDR_LEN);
        NdisMoveMemory(RespEth->SrcMac, OrigEth->DstMac, DNS_ETH_ADDR_LEN);
    }

    // 2. L3 header (swap SrcIp <-> DstIp)
    if (Frame.AddressFamily == REDIRECT_AF_IPV4)
    {
        PDNS_IPV4_HDR Ip4 = (PDNS_IPV4_HDR)(RespBuf + Frame.IpOffset);
        Ip4->VerIhl = 0x45;
        Ip4->Tos = 0;
        Ip4->TotalLength = RtlUshortByteSwap((USHORT)(RespIpHdrLen + RespUdpLen));
        Ip4->Identification = Frame.Ipv4Id;
        Ip4->FlagsFragOffset = 0;
        Ip4->Ttl = 64;
        Ip4->Protocol = DNS_PROTO_UDP;
        NdisMoveMemory(Ip4->SrcAddr, Frame.DstIp, 4);
        NdisMoveMemory(Ip4->DstAddr, Frame.SrcIp, 4);
        DnsCalcIpv4HeaderChecksum(Ip4);
    }
    else
    {
        PDNS_IPV6_HDR Ip6 = (PDNS_IPV6_HDR)(RespBuf + Frame.IpOffset);
        Ip6->VerTcHi = 0x60;
        Ip6->TcLoFlowHi = 0;
        Ip6->FlowLo = 0;
        Ip6->PayloadLength = RtlUshortByteSwap((USHORT)RespUdpLen);
        Ip6->NextHeader = DNS_PROTO_UDP;
        Ip6->HopLimit = 64;
        NdisMoveMemory(Ip6->SrcAddr, Frame.DstIp, 16);
        NdisMoveMemory(Ip6->DstAddr, Frame.SrcIp, 16);
    }

    // 3. L4 UDP header + DNS response payload
    {
        PUCHAR          UdpPtr = RespBuf + Frame.IpOffset + RespIpHdrLen;
        PDNS_UDP_HDR    Udp = (PDNS_UDP_HDR)UdpPtr;
        PUCHAR          RespDns = UdpPtr + sizeof(DNS_UDP_HDR);
        PDNS_WIRE_HDR   DnsHdr = (PDNS_WIRE_HDR)RespDns;
        const UCHAR    *OrigDns = QueryBuf + Frame.UdpOffset + sizeof(DNS_UDP_HDR);
        USHORT          RespFlagsHost;

        Udp->SrcPort = Frame.DstPort;
        Udp->DstPort = Frame.SrcPort;
        Udp->Length = RtlUshortByteSwap((USHORT)RespUdpLen);
        Udp->Checksum = 0;

        // Copy Transaction ID + preserve RD bit; set QR=1, RA=1, RCODE=0
        DnsHdr->TransactionId = ((const DNS_WIRE_HDR *)OrigDns)->TransactionId;
        RespFlagsHost = (USHORT)(0x8080 | (OrigDnsFlags & 0x0100));
        DnsHdr->Flags = RtlUshortByteSwap(RespFlagsHost);
        DnsHdr->QuestionCount = RtlUshortByteSwap(1);
        DnsHdr->AnswerCount = RtlUshortByteSwap(HasAnswer ? 1 : 0);
        DnsHdr->AuthorityCount = 0;
        DnsHdr->AdditionalCount = 0;

        // Copy Question section verbatim
        NdisMoveMemory(RespDns + DNS_HEADER_LEN, OrigDns + DNS_HEADER_LEN, QSectionLen);

        if (HasAnswer)
        {
            PUCHAR  Ans = RespDns + DNS_HEADER_LEN + QSectionLen;
            ULONG   TtlNet = RtlUlongByteSwap(Rule.Ttl);

            // Compressed NAME pointer to offset 12 (0xC00C)
            Ans[0] = 0xC0;
            Ans[1] = 0x0C;
            // TYPE
            Ans[2] = (UCHAR)((QType >> 8) & 0xFF);
            Ans[3] = (UCHAR)(QType & 0xFF);
            // CLASS = IN (1)
            Ans[4] = 0x00;
            Ans[5] = 0x01;
            // TTL (4 bytes network byte order)
            NdisMoveMemory(Ans + 6, &TtlNet, 4);
            // RDLENGTH
            Ans[10] = (UCHAR)((AnswerRdLen >> 8) & 0xFF);
            Ans[11] = (UCHAR)(AnswerRdLen & 0xFF);
            // RDATA
            if (QType == DNS_TYPE_A)
            {
                NdisMoveMemory(Ans + 12, Rule.FakeIpv4, 4);
            }
            else
            {
                NdisMoveMemory(Ans + 12, Rule.FakeIpv6, 16);
            }
        }

        Udp->Checksum = DnsCalcUdpChecksum(
                            Frame.AddressFamily,
                            Frame.DstIp,    // Response SrcIp = Query DstIp
                            Frame.SrcIp,    // Response DstIp = Query SrcIp
                            UdpPtr,
                            RespUdpLen);
    }

    Injected = RedirectInjectLocalPacket(pFilter, RespBuf, RespTotalLen, DispatchLevel);

Exit:
    if (RespBuf != NULL)
    {
        NdisFreeMemory(RespBuf, 0, 0);
    }
    if (QueryBuf != NULL)
    {
        NdisFreeMemory(QueryBuf, 0, 0);
    }
    return Injected;
}
