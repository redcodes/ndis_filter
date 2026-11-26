/*++

Module Name:

    redirect.c

Abstract:

    IPv4/IPv6 IP address and port redirection engine for NDIS 6.0 LWF.
    Supports:
    - Outbound destination rewrite (DNAT) and stateful inbound restore
    - Optional destination MAC rewrite for same-subnet different-host redirect
    - Local host loopback redirect via async receive indication (auto-detected
      when NewIp equals outbound SrcIp, or forced via REDIRECT_FLAG_LOCAL_LOOPBACK)

--*/

#include "precomp.h"

#define __FILENUMBER    'RDIR'

//
// Protocol constants
//
#define ETH_ADDR_LEN                6
#define ETH_TYPE_IPV4               0x0800
#define ETH_TYPE_IPV6               0x86DD
#define ETH_TYPE_VLAN               0x8100
#define ETH_TYPE_QINQ               0x88A8

#define IPV6_NEXTHDR_HOPBYHOP       0
#define IPV6_NEXTHDR_ROUTING        43
#define IPV6_NEXTHDR_FRAGMENT       44
#define IPV6_NEXTHDR_DSTOPTS        60

#define TCP_FLAG_FIN                0x01
#define TCP_FLAG_PSH                0x08
#define TCP_FLAG_CWR                0x80

#define REDIRECT_PEEK_SIZE          128
#define REDIRECT_MAX_VLAN_DEPTH     2
#define REDIRECT_MAX_IPV6_EXT       8
#define REDIRECT_DEFAULT_MSS_V4     1460
#define REDIRECT_DEFAULT_MSS_V6     1440

#define REDIRECT_SESSION_BUCKETS    256
#define REDIRECT_MAX_SESSIONS       4096
#define REDIRECT_SESSION_TIMEOUT    (120LL * 10000000LL) // 120s in 100ns units

//
// Packed network headers
//
#include <pshpack1.h>

typedef struct _ETH_HEADER
{
    UCHAR       DstMac[ETH_ADDR_LEN];
    UCHAR       SrcMac[ETH_ADDR_LEN];
    USHORT      EtherType;
} ETH_HEADER, *PETH_HEADER;

typedef struct _VLAN_HEADER
{
    USHORT      Tci;
    USHORT      EtherType;
} VLAN_HEADER, *PVLAN_HEADER;

typedef struct _IPV4_HEADER
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
} IPV4_HEADER, *PIPV4_HEADER;

typedef struct _IPV6_HEADER
{
    UCHAR       VerTcHi;
    UCHAR       TcLoFlowHi;
    USHORT      FlowLo;
    USHORT      PayloadLength;
    UCHAR       NextHeader;
    UCHAR       HopLimit;
    UCHAR       SrcAddr[16];
    UCHAR       DstAddr[16];
} IPV6_HEADER, *PIPV6_HEADER;

typedef struct _IPV6_EXT_HEADER
{
    UCHAR       NextHeader;
    UCHAR       HdrExtLen;
} IPV6_EXT_HEADER, *PIPV6_EXT_HEADER;

typedef struct _IPV6_FRAG_HEADER
{
    UCHAR       NextHeader;
    UCHAR       Reserved;
    USHORT      FragOffsetResM;
    ULONG       Identification;
} IPV6_FRAG_HEADER, *PIPV6_FRAG_HEADER;

typedef struct _TCP_HEADER
{
    USHORT      SrcPort;
    USHORT      DstPort;
    ULONG       SeqNum;
    ULONG       AckNum;
    UCHAR       DataOffsetRes;
    UCHAR       Flags;
    USHORT      Window;
    USHORT      Checksum;
    USHORT      UrgentPtr;
} TCP_HEADER, *PTCP_HEADER;

typedef struct _UDP_HEADER
{
    USHORT      SrcPort;
    USHORT      DstPort;
    USHORT      Length;
    USHORT      Checksum;
} UDP_HEADER, *PUDP_HEADER;

#include <poppack.h>

//
// Parsed header metadata
//
typedef struct _PARSED_PACKET_INFO
{
    UCHAR               AddressFamily;
    UCHAR               Protocol;
    ULONG               IpHeaderOffset;
    ULONG               IpHeaderLength;
    ULONG               L4HeaderOffset;
    ULONG               IpPayloadL4Len; // 0 when LSOv2 leaves IP length 0
    REDIRECT_IP_ADDR    SrcIp;
    REDIRECT_IP_ADDR    DstIp;
    USHORT              SrcPort;        // Network byte order
    USHORT              DstPort;        // Network byte order
    UCHAR               SrcMac[ETH_ADDR_LEN];
    UCHAR               DstMac[ETH_ADDR_LEN];
} PARSED_PACKET_INFO, *PPARSED_PACKET_INFO;

//
// Lightweight NAT session entry
// - External redirect (IsLocalLoopback == FALSE):
//     Key   = (AF, Proto, LocalIp=ClientIp, LocalPort=ClientPort, NewDstIp, NewDstPort)
//     Value = (OrigDstIp, OrigDstPort, OrigDstMac)
// - Local loopback redirect (IsLocalLoopback == TRUE):
//     Key   = (AF, Proto, LocalIp=ServerIp, LocalPort=ServerPort, NewDstIp=OrigDstIp, NewDstPort=ClientPort)
//     Value = (OrigDstIp, OrigDstPort, ClientIp)
//
typedef struct _REDIRECT_SESSION
{
    LIST_ENTRY          HashLink;
    LIST_ENTRY          LruLink;
    ULONG               RuleId;
    UCHAR               AddressFamily;
    UCHAR               Protocol;
    BOOLEAN             HasOrigDstMac;
    BOOLEAN             IsLocalLoopback;
    REDIRECT_IP_ADDR    LocalIp;
    USHORT              LocalPort;      // Network byte order
    USHORT              NewDstPort;     // Network byte order
    REDIRECT_IP_ADDR    NewDstIp;
    REDIRECT_IP_ADDR    OrigDstIp;
    REDIRECT_IP_ADDR    ClientIp;       // Used when IsLocalLoopback == TRUE
    USHORT              OrigDstPort;    // Network byte order
    UCHAR               OrigDstMac[ETH_ADDR_LEN];
    LARGE_INTEGER       LastActiveTime;
} REDIRECT_SESSION, *PREDIRECT_SESSION;

//
// Global redirect state
//
static BOOLEAN          gRedirectInitialized = FALSE;

static NDIS_RW_LOCK     gRuleLock;
static REDIRECT_RULE    gRules[MAX_REDIRECT_RULES];
static ULONG            gRuleCount = 0;
static ULONG            gNextRuleId = 1;

static FILTER_LOCK      gSessionLock;
static LIST_ENTRY       gSessionBuckets[REDIRECT_SESSION_BUCKETS];
static LIST_ENTRY       gSessionLru;
static ULONG            gSessionCount = 0;

//
// Forward declaration for async local loopback receive injection DPC
//
KDEFERRED_ROUTINE RedirectInjectDpcRoutine;

//
// Helper functions: IP address utilities
//
static
__inline
ULONG
RedirectIpByteLen(
    IN UCHAR    AddressFamily
    )
{
    return (AddressFamily == REDIRECT_AF_IPV6) ? 16 : 4;
}

static
__inline
BOOLEAN
RedirectIpEqual(
    IN UCHAR                    AddressFamily,
    IN const REDIRECT_IP_ADDR  *A,
    IN const REDIRECT_IP_ADDR  *B
    )
{
    ULONG Len = RedirectIpByteLen(AddressFamily);
    return (RtlCompareMemory(A, B, Len) == Len) ? TRUE : FALSE;
}

static
__inline
VOID
RedirectCopyIp(
    IN  UCHAR                   AddressFamily,
    OUT PREDIRECT_IP_ADDR       Dst,
    IN  const VOID             *SrcBytes
    )
{
    ULONG Len = RedirectIpByteLen(AddressFamily);
    NdisZeroMemory(Dst, sizeof(REDIRECT_IP_ADDR));
    NdisMoveMemory(Dst, SrcBytes, Len);
}

static
ULONG
RedirectHashSessionKey(
    IN UCHAR                    AddressFamily,
    IN UCHAR                    Protocol,
    IN BOOLEAN                  IsLocalLoopback,
    IN const REDIRECT_IP_ADDR  *LocalIp,
    IN USHORT                   LocalPort,
    IN const REDIRECT_IP_ADDR  *RemoteIp,
    IN USHORT                   RemotePort
    )
{
    ULONG   Hash = 2166136261UL;
    ULONG   Len = RedirectIpByteLen(AddressFamily);
    ULONG   i;

    Hash = (Hash ^ AddressFamily) * 16777619UL;
    Hash = (Hash ^ Protocol) * 16777619UL;
    Hash = (Hash ^ (IsLocalLoopback ? 1UL : 0UL)) * 16777619UL;
    Hash = (Hash ^ LocalPort) * 16777619UL;
    Hash = (Hash ^ RemotePort) * 16777619UL;

    for (i = 0; i < Len; i++)
    {
        Hash = (Hash ^ LocalIp->V6[i]) * 16777619UL;
        Hash = (Hash ^ RemoteIp->V6[i]) * 16777619UL;
    }

    return Hash & (REDIRECT_SESSION_BUCKETS - 1);
}

//
// Helper functions: Checksums (big-endian byte accumulation, endianness-safe)
//
static
ULONG
RedirectSumBytesBe(
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
__inline
USHORT
RedirectFoldSum(
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
RedirectRecalcIpv4Checksum(
    IN OUT PIPV4_HEADER Ip4,
    IN     ULONG        Ihl
    )
{
    ULONG   Sum;
    USHORT  Folded;

    Ip4->HeaderChecksum = 0;
    Sum = RedirectSumBytesBe((const UCHAR *)Ip4, Ihl, 0);
    Folded = (USHORT)(~RedirectFoldSum(Sum));
    Ip4->HeaderChecksum = RtlUshortByteSwap(Folded);
}

static
USHORT
RedirectCalcPseudoHeaderSum(
    IN UCHAR        AddressFamily,
    IN UCHAR        Protocol,
    IN const UCHAR *SrcIp,
    IN const UCHAR *DstIp,
    IN ULONG        L4Len,
    IN BOOLEAN      IncludeLength
    )
{
    ULONG   Sum = 0;

    if (AddressFamily == REDIRECT_AF_IPV4)
    {
        Sum = RedirectSumBytesBe(SrcIp, 4, Sum);
        Sum = RedirectSumBytesBe(DstIp, 4, Sum);
        Sum += (ULONG)Protocol;
        if (IncludeLength)
        {
            Sum += (L4Len & 0xFFFFUL);
        }
    }
    else
    {
        Sum = RedirectSumBytesBe(SrcIp, 16, Sum);
        Sum = RedirectSumBytesBe(DstIp, 16, Sum);
        if (IncludeLength)
        {
            Sum += ((L4Len >> 16) & 0xFFFFUL);
            Sum += (L4Len & 0xFFFFUL);
        }
        Sum += (ULONG)Protocol;
    }

    return RedirectFoldSum(Sum);
}

static
VOID
RedirectRecalcL4Checksum(
    IN     UCHAR        AddressFamily,
    IN     UCHAR        Protocol,
    IN     const UCHAR *SrcIp,
    IN     const UCHAR *DstIp,
    IN OUT PUCHAR       L4Header,
    IN     ULONG        L4Len,
    IN     BOOLEAN      KeepZeroUdpV4
    )
{
    ULONG   Sum;
    USHORT  CsumHost;

    if (Protocol == REDIRECT_PROTO_TCP)
    {
        PTCP_HEADER Tcp = (PTCP_HEADER)L4Header;

        Tcp->Checksum = 0;
        Sum = RedirectCalcPseudoHeaderSum(AddressFamily, Protocol, SrcIp, DstIp, L4Len, TRUE);
        Sum = RedirectSumBytesBe(L4Header, L4Len, Sum);
        CsumHost = (USHORT)(~RedirectFoldSum(Sum));
        Tcp->Checksum = RtlUshortByteSwap(CsumHost);
    }
    else if (Protocol == REDIRECT_PROTO_UDP)
    {
        PUDP_HEADER Udp = (PUDP_HEADER)L4Header;

        if (KeepZeroUdpV4 && AddressFamily == REDIRECT_AF_IPV4 && Udp->Checksum == 0)
        {
            return;
        }

        Udp->Checksum = 0;
        Sum = RedirectCalcPseudoHeaderSum(AddressFamily, Protocol, SrcIp, DstIp, L4Len, TRUE);
        Sum = RedirectSumBytesBe(L4Header, L4Len, Sum);
        CsumHost = (USHORT)(~RedirectFoldSum(Sum));
        if (CsumHost == 0)
        {
            CsumHost = 0xFFFF;
        }
        Udp->Checksum = RtlUshortByteSwap(CsumHost);
    }
}

//
// Helper function: Packet header parser (Ethernet + VLAN + IPv4/IPv6 + TCP/UDP)
//
static
BOOLEAN
RedirectParsePacketHeaders(
    IN  const UCHAR        *Data,
    IN  ULONG               DataLen,
    OUT PPARSED_PACKET_INFO Info
    )
{
    const ETH_HEADER   *Eth;
    USHORT              EtherType;
    ULONG               Offset;
    ULONG               VlanDepth;

    if (DataLen < sizeof(ETH_HEADER))
    {
        return FALSE;
    }

    NdisZeroMemory(Info, sizeof(PARSED_PACKET_INFO));

    Eth = (const ETH_HEADER *)Data;
    NdisMoveMemory(Info->DstMac, Eth->DstMac, ETH_ADDR_LEN);
    NdisMoveMemory(Info->SrcMac, Eth->SrcMac, ETH_ADDR_LEN);

    EtherType = RtlUshortByteSwap(Eth->EtherType);
    Offset = sizeof(ETH_HEADER);

    for (VlanDepth = 0;
         VlanDepth < REDIRECT_MAX_VLAN_DEPTH &&
         (EtherType == ETH_TYPE_VLAN || EtherType == ETH_TYPE_QINQ);
         VlanDepth++)
    {
        const VLAN_HEADER *Vlan;

        if (Offset + sizeof(VLAN_HEADER) > DataLen)
        {
            return FALSE;
        }

        Vlan = (const VLAN_HEADER *)(Data + Offset);
        EtherType = RtlUshortByteSwap(Vlan->EtherType);
        Offset += sizeof(VLAN_HEADER);
    }

    Info->IpHeaderOffset = Offset;

    if (EtherType == ETH_TYPE_IPV4)
    {
        const IPV4_HEADER  *Ip4;
        ULONG               Ihl;
        USHORT              TotalLen;
        USHORT              FragField;

        if (Offset + sizeof(IPV4_HEADER) > DataLen)
        {
            return FALSE;
        }

        Ip4 = (const IPV4_HEADER *)(Data + Offset);
        if ((Ip4->VerIhl >> 4) != 4)
        {
            return FALSE;
        }

        Ihl = (ULONG)(Ip4->VerIhl & 0x0F) * 4;
        if (Ihl < sizeof(IPV4_HEADER) || Offset + Ihl > DataLen)
        {
            return FALSE;
        }

        FragField = RtlUshortByteSwap(Ip4->FlagsFragOffset);
        if ((FragField & 0x1FFF) != 0)
        {
            return FALSE;
        }

        if (Ip4->Protocol != REDIRECT_PROTO_TCP && Ip4->Protocol != REDIRECT_PROTO_UDP)
        {
            return FALSE;
        }

        TotalLen = RtlUshortByteSwap(Ip4->TotalLength);
        if (TotalLen != 0 && TotalLen < Ihl)
        {
            return FALSE;
        }

        Info->AddressFamily = REDIRECT_AF_IPV4;
        Info->Protocol = Ip4->Protocol;
        Info->IpHeaderLength = Ihl;
        Info->L4HeaderOffset = Offset + Ihl;
        Info->IpPayloadL4Len = (TotalLen >= Ihl) ? (ULONG)(TotalLen - Ihl) : 0;
        RedirectCopyIp(REDIRECT_AF_IPV4, &Info->SrcIp, Ip4->SrcAddr);
        RedirectCopyIp(REDIRECT_AF_IPV4, &Info->DstIp, Ip4->DstAddr);
    }
    else if (EtherType == ETH_TYPE_IPV6)
    {
        const IPV6_HEADER  *Ip6;
        UCHAR               NextHdr;
        ULONG               ExtOffset;
        ULONG               ExtTotalLen = 0;
        ULONG               ExtCount;
        USHORT              PayloadLen;

        if (Offset + sizeof(IPV6_HEADER) > DataLen)
        {
            return FALSE;
        }

        Ip6 = (const IPV6_HEADER *)(Data + Offset);
        if ((Ip6->VerTcHi >> 4) != 6)
        {
            return FALSE;
        }

        PayloadLen = RtlUshortByteSwap(Ip6->PayloadLength);
        NextHdr = Ip6->NextHeader;
        ExtOffset = Offset + sizeof(IPV6_HEADER);

        for (ExtCount = 0; ExtCount < REDIRECT_MAX_IPV6_EXT; ExtCount++)
        {
            if (NextHdr == REDIRECT_PROTO_TCP || NextHdr == REDIRECT_PROTO_UDP)
            {
                break;
            }
            else if (NextHdr == IPV6_NEXTHDR_HOPBYHOP ||
                     NextHdr == IPV6_NEXTHDR_ROUTING ||
                     NextHdr == IPV6_NEXTHDR_DSTOPTS)
            {
                const IPV6_EXT_HEADER  *Ext;
                ULONG                   HdrLen;

                if (ExtOffset + sizeof(IPV6_EXT_HEADER) > DataLen)
                {
                    return FALSE;
                }

                Ext = (const IPV6_EXT_HEADER *)(Data + ExtOffset);
                HdrLen = ((ULONG)Ext->HdrExtLen + 1) * 8;
                if (ExtOffset + HdrLen > DataLen)
                {
                    return FALSE;
                }

                NextHdr = Ext->NextHeader;
                ExtOffset += HdrLen;
                ExtTotalLen += HdrLen;
            }
            else if (NextHdr == IPV6_NEXTHDR_FRAGMENT)
            {
                const IPV6_FRAG_HEADER *Frag;
                USHORT                  FragOffset;

                if (ExtOffset + sizeof(IPV6_FRAG_HEADER) > DataLen)
                {
                    return FALSE;
                }

                Frag = (const IPV6_FRAG_HEADER *)(Data + ExtOffset);
                FragOffset = RtlUshortByteSwap(Frag->FragOffsetResM);
                if ((FragOffset & 0xFFF8) != 0)
                {
                    return FALSE;
                }

                NextHdr = Frag->NextHeader;
                ExtOffset += sizeof(IPV6_FRAG_HEADER);
                ExtTotalLen += sizeof(IPV6_FRAG_HEADER);
            }
            else
            {
                return FALSE;
            }
        }

        if (NextHdr != REDIRECT_PROTO_TCP && NextHdr != REDIRECT_PROTO_UDP)
        {
            return FALSE;
        }

        if (PayloadLen != 0 && PayloadLen < ExtTotalLen)
        {
            return FALSE;
        }

        Info->AddressFamily = REDIRECT_AF_IPV6;
        Info->Protocol = NextHdr;
        Info->IpHeaderLength = sizeof(IPV6_HEADER) + ExtTotalLen;
        Info->L4HeaderOffset = ExtOffset;
        Info->IpPayloadL4Len = (PayloadLen >= ExtTotalLen) ? (ULONG)(PayloadLen - ExtTotalLen) : 0;
        RedirectCopyIp(REDIRECT_AF_IPV6, &Info->SrcIp, Ip6->SrcAddr);
        RedirectCopyIp(REDIRECT_AF_IPV6, &Info->DstIp, Ip6->DstAddr);
    }
    else
    {
        return FALSE;
    }

    if (Info->Protocol == REDIRECT_PROTO_TCP)
    {
        const TCP_HEADER *Tcp;

        if (Info->L4HeaderOffset + sizeof(TCP_HEADER) > DataLen)
        {
            return FALSE;
        }

        Tcp = (const TCP_HEADER *)(Data + Info->L4HeaderOffset);
        Info->SrcPort = Tcp->SrcPort;
        Info->DstPort = Tcp->DstPort;
    }
    else
    {
        const UDP_HEADER *Udp;

        if (Info->L4HeaderOffset + sizeof(UDP_HEADER) > DataLen)
        {
            return FALSE;
        }

        Udp = (const UDP_HEADER *)(Data + Info->L4HeaderOffset);
        Info->SrcPort = Udp->SrcPort;
        Info->DstPort = Udp->DstPort;
    }

    return TRUE;
}

//
// Helper functions: Session table
//
static
VOID
RedirectPurgeSessionsByRuleId(
    IN ULONG    RuleId,
    IN BOOLEAN  ClearAll
    )
{
    PLIST_ENTRY         Entry;
    PLIST_ENTRY         NextEntry;
    PREDIRECT_SESSION   Session;
    LIST_ENTRY          FreeList;
    BOOLEAN             bFalse = FALSE;

    InitializeListHead(&FreeList);

    FILTER_ACQUIRE_LOCK(&gSessionLock, bFalse);

    Entry = gSessionLru.Flink;
    while (Entry != &gSessionLru)
    {
        NextEntry = Entry->Flink;
        Session = CONTAINING_RECORD(Entry, REDIRECT_SESSION, LruLink);

        if (ClearAll || Session->RuleId == RuleId)
        {
            RemoveEntryList(&Session->HashLink);
            RemoveEntryList(&Session->LruLink);
            gSessionCount--;
            InsertTailList(&FreeList, &Session->LruLink);
        }

        Entry = NextEntry;
    }

    FILTER_RELEASE_LOCK(&gSessionLock, bFalse);

    while (!IsListEmpty(&FreeList))
    {
        Entry = RemoveHeadList(&FreeList);
        Session = CONTAINING_RECORD(Entry, REDIRECT_SESSION, LruLink);
        ExFreePoolWithTag(Session, FILTER_ALLOC_TAG);
    }
}

static
VOID
RedirectUpsertSessionInternal(
    IN UCHAR                    AddressFamily,
    IN UCHAR                    Protocol,
    IN BOOLEAN                  IsLocalLoopback,
    IN const REDIRECT_IP_ADDR  *KeyLocalIp,
    IN USHORT                   KeyLocalPort,
    IN const REDIRECT_IP_ADDR  *KeyRemoteIp,
    IN USHORT                   KeyRemotePort,
    IN ULONG                    RuleId,
    IN const REDIRECT_IP_ADDR  *OrigDstIp,
    IN USHORT                   OrigDstPort,
    IN const REDIRECT_IP_ADDR  *ClientIp,
    IN BOOLEAN                  HasOrigDstMac,
    IN const UCHAR             *OrigDstMac,
    IN BOOLEAN                  DispatchLevel
    )
{
    ULONG               Bucket;
    PLIST_ENTRY         Entry;
    PREDIRECT_SESSION   Session = NULL;
    LARGE_INTEGER       Now;

    NdisGetCurrentSystemTime(&Now);
    Bucket = RedirectHashSessionKey(
                 AddressFamily,
                 Protocol,
                 IsLocalLoopback,
                 KeyLocalIp,
                 KeyLocalPort,
                 KeyRemoteIp,
                 KeyRemotePort);

    FILTER_ACQUIRE_LOCK(&gSessionLock, DispatchLevel);

    Entry = gSessionBuckets[Bucket].Flink;
    while (Entry != &gSessionBuckets[Bucket])
    {
        PREDIRECT_SESSION Cand = CONTAINING_RECORD(Entry, REDIRECT_SESSION, HashLink);

        if (Cand->IsLocalLoopback == IsLocalLoopback &&
            Cand->AddressFamily == AddressFamily &&
            Cand->Protocol == Protocol &&
            Cand->LocalPort == KeyLocalPort &&
            Cand->NewDstPort == KeyRemotePort &&
            RedirectIpEqual(AddressFamily, &Cand->LocalIp, KeyLocalIp) &&
            RedirectIpEqual(AddressFamily, &Cand->NewDstIp, KeyRemoteIp))
        {
            Session = Cand;
            break;
        }

        Entry = Entry->Flink;
    }

    if (Session != NULL)
    {
        RemoveEntryList(&Session->LruLink);
        InsertHeadList(&gSessionLru, &Session->LruLink);
    }
    else
    {
        if (gSessionCount >= REDIRECT_MAX_SESSIONS && !IsListEmpty(&gSessionLru))
        {
            Entry = RemoveTailList(&gSessionLru);
            Session = CONTAINING_RECORD(Entry, REDIRECT_SESSION, LruLink);
            RemoveEntryList(&Session->HashLink);
        }
        else
        {
            Session = (PREDIRECT_SESSION)ExAllocatePoolWithTag(
                                             NonPagedPool,
                                             sizeof(REDIRECT_SESSION),
                                             FILTER_ALLOC_TAG);
            if (Session != NULL)
            {
                gSessionCount++;
            }
        }

        if (Session != NULL)
        {
            NdisZeroMemory(Session, sizeof(REDIRECT_SESSION));
            Session->IsLocalLoopback = IsLocalLoopback;
            Session->AddressFamily = AddressFamily;
            Session->Protocol = Protocol;
            RedirectCopyIp(AddressFamily, &Session->LocalIp, KeyLocalIp);
            Session->LocalPort = KeyLocalPort;
            RedirectCopyIp(AddressFamily, &Session->NewDstIp, KeyRemoteIp);
            Session->NewDstPort = KeyRemotePort;

            InsertHeadList(&gSessionBuckets[Bucket], &Session->HashLink);
            InsertHeadList(&gSessionLru, &Session->LruLink);
        }
    }

    if (Session != NULL)
    {
        Session->RuleId = RuleId;
        RedirectCopyIp(AddressFamily, &Session->OrigDstIp, OrigDstIp);
        Session->OrigDstPort = OrigDstPort;
        if (ClientIp != NULL)
        {
            RedirectCopyIp(AddressFamily, &Session->ClientIp, ClientIp);
        }
        Session->HasOrigDstMac = HasOrigDstMac;
        if (HasOrigDstMac && OrigDstMac != NULL)
        {
            NdisMoveMemory(Session->OrigDstMac, OrigDstMac, ETH_ADDR_LEN);
        }
        Session->LastActiveTime = Now;
    }

    FILTER_RELEASE_LOCK(&gSessionLock, DispatchLevel);
}

static
VOID
RedirectUpsertExternalSession(
    IN const PARSED_PACKET_INFO    *PktInfo,
    IN const REDIRECT_RULE         *Rule,
    IN USHORT                       EffectiveNewPort,
    IN BOOLEAN                      DispatchLevel
    )
{
    RedirectUpsertSessionInternal(
        PktInfo->AddressFamily,
        PktInfo->Protocol,
        FALSE,
        &PktInfo->SrcIp,
        PktInfo->SrcPort,
        &Rule->NewIp,
        EffectiveNewPort,
        Rule->RuleId,
        &PktInfo->DstIp,
        PktInfo->DstPort,
        NULL,
        ((Rule->Flags & REDIRECT_FLAG_REWRITE_MAC) != 0) ? TRUE : FALSE,
        PktInfo->DstMac,
        DispatchLevel);
}

static
VOID
RedirectUpsertLocalSession(
    IN const PARSED_PACKET_INFO    *PktInfo,
    IN const REDIRECT_RULE         *Rule,
    IN USHORT                       EffectiveNewPort,
    IN BOOLEAN                      DispatchLevel
    )
{
    // Local server reply will have:
    //   SrcIp = Rule->NewIp, SrcPort = EffectiveNewPort
    //   DstIp = PktInfo->DstIp (OrigDstIp), DstPort = PktInfo->SrcPort (ClientPort)
    RedirectUpsertSessionInternal(
        PktInfo->AddressFamily,
        PktInfo->Protocol,
        TRUE,
        &Rule->NewIp,
        EffectiveNewPort,
        &PktInfo->DstIp,
        PktInfo->SrcPort,
        Rule->RuleId,
        &PktInfo->DstIp,
        PktInfo->DstPort,
        &PktInfo->SrcIp,
        FALSE,
        NULL,
        DispatchLevel);
}

static
BOOLEAN
RedirectLookupExternalSession(
    IN  const PARSED_PACKET_INFO   *PktInfo,
    IN  BOOLEAN                     DispatchLevel,
    OUT PREDIRECT_IP_ADDR           OrigSrcIp,
    OUT PUSHORT                     OrigSrcPort,
    OUT PUCHAR                      OrigSrcMac,
    OUT PBOOLEAN                    RestoreSrcMac
    )
{
    ULONG               Bucket;
    PLIST_ENTRY         Entry;
    PLIST_ENTRY         NextEntry;
    PREDIRECT_SESSION   ExpiredSession = NULL;
    LARGE_INTEGER       Now;
    BOOLEAN             Found = FALSE;

    NdisGetCurrentSystemTime(&Now);
    Bucket = RedirectHashSessionKey(
                 PktInfo->AddressFamily,
                 PktInfo->Protocol,
                 FALSE,
                 &PktInfo->DstIp,
                 PktInfo->DstPort,
                 &PktInfo->SrcIp,
                 PktInfo->SrcPort);

    FILTER_ACQUIRE_LOCK(&gSessionLock, DispatchLevel);

    Entry = gSessionBuckets[Bucket].Flink;
    while (Entry != &gSessionBuckets[Bucket])
    {
        PREDIRECT_SESSION Cand = CONTAINING_RECORD(Entry, REDIRECT_SESSION, HashLink);
        NextEntry = Entry->Flink;

        if (!Cand->IsLocalLoopback &&
            Cand->AddressFamily == PktInfo->AddressFamily &&
            Cand->Protocol == PktInfo->Protocol &&
            Cand->LocalPort == PktInfo->DstPort &&
            Cand->NewDstPort == PktInfo->SrcPort &&
            RedirectIpEqual(PktInfo->AddressFamily, &Cand->LocalIp, &PktInfo->DstIp) &&
            RedirectIpEqual(PktInfo->AddressFamily, &Cand->NewDstIp, &PktInfo->SrcIp))
        {
            if ((Now.QuadPart - Cand->LastActiveTime.QuadPart) > REDIRECT_SESSION_TIMEOUT)
            {
                RemoveEntryList(&Cand->HashLink);
                RemoveEntryList(&Cand->LruLink);
                gSessionCount--;
                ExpiredSession = Cand;
            }
            else
            {
                Cand->LastActiveTime = Now;
                RemoveEntryList(&Cand->LruLink);
                InsertHeadList(&gSessionLru, &Cand->LruLink);

                RedirectCopyIp(PktInfo->AddressFamily, OrigSrcIp, &Cand->OrigDstIp);
                *OrigSrcPort = Cand->OrigDstPort;
                *RestoreSrcMac = Cand->HasOrigDstMac;
                if (Cand->HasOrigDstMac)
                {
                    NdisMoveMemory(OrigSrcMac, Cand->OrigDstMac, ETH_ADDR_LEN);
                }
                Found = TRUE;
            }
            break;
        }

        Entry = NextEntry;
    }

    FILTER_RELEASE_LOCK(&gSessionLock, DispatchLevel);

    if (ExpiredSession != NULL)
    {
        ExFreePoolWithTag(ExpiredSession, FILTER_ALLOC_TAG);
    }

    return Found;
}

static
BOOLEAN
RedirectLookupLocalReplySession(
    IN  const PARSED_PACKET_INFO   *PktInfo,
    IN  BOOLEAN                     DispatchLevel,
    OUT PREDIRECT_IP_ADDR           OrigDstIp,
    OUT PUSHORT                     OrigDstPort,
    OUT PREDIRECT_IP_ADDR           ClientIp
    )
{
    ULONG               Bucket;
    PLIST_ENTRY         Entry;
    PLIST_ENTRY         NextEntry;
    PREDIRECT_SESSION   ExpiredSession = NULL;
    LARGE_INTEGER       Now;
    BOOLEAN             Found = FALSE;

    if (gSessionCount == 0)
    {
        return FALSE;
    }

    NdisGetCurrentSystemTime(&Now);
    Bucket = RedirectHashSessionKey(
                 PktInfo->AddressFamily,
                 PktInfo->Protocol,
                 TRUE,
                 &PktInfo->SrcIp,
                 PktInfo->SrcPort,
                 &PktInfo->DstIp,
                 PktInfo->DstPort);

    FILTER_ACQUIRE_LOCK(&gSessionLock, DispatchLevel);

    Entry = gSessionBuckets[Bucket].Flink;
    while (Entry != &gSessionBuckets[Bucket])
    {
        PREDIRECT_SESSION Cand = CONTAINING_RECORD(Entry, REDIRECT_SESSION, HashLink);
        NextEntry = Entry->Flink;

        if (Cand->IsLocalLoopback &&
            Cand->AddressFamily == PktInfo->AddressFamily &&
            Cand->Protocol == PktInfo->Protocol &&
            Cand->LocalPort == PktInfo->SrcPort &&
            Cand->NewDstPort == PktInfo->DstPort &&
            RedirectIpEqual(PktInfo->AddressFamily, &Cand->LocalIp, &PktInfo->SrcIp) &&
            RedirectIpEqual(PktInfo->AddressFamily, &Cand->NewDstIp, &PktInfo->DstIp))
        {
            if ((Now.QuadPart - Cand->LastActiveTime.QuadPart) > REDIRECT_SESSION_TIMEOUT)
            {
                RemoveEntryList(&Cand->HashLink);
                RemoveEntryList(&Cand->LruLink);
                gSessionCount--;
                ExpiredSession = Cand;
            }
            else
            {
                Cand->LastActiveTime = Now;
                RemoveEntryList(&Cand->LruLink);
                InsertHeadList(&gSessionLru, &Cand->LruLink);

                RedirectCopyIp(PktInfo->AddressFamily, OrigDstIp, &Cand->OrigDstIp);
                *OrigDstPort = Cand->OrigDstPort;
                RedirectCopyIp(PktInfo->AddressFamily, ClientIp, &Cand->ClientIp);
                Found = TRUE;
            }
            break;
        }

        Entry = NextEntry;
    }

    FILTER_RELEASE_LOCK(&gSessionLock, DispatchLevel);

    if (ExpiredSession != NULL)
    {
        ExFreePoolWithTag(ExpiredSession, FILTER_ALLOC_TAG);
    }

    return Found;
}

//
// Helper function: Match outbound packet against configured rules
//
static
BOOLEAN
RedirectMatchOutboundRule(
    IN  const PARSED_PACKET_INFO   *PktInfo,
    OUT PREDIRECT_RULE              MatchedRule
    )
{
    LOCK_STATE  LockState;
    ULONG       i;
    BOOLEAN     Found = FALSE;

    NdisAcquireReadWriteLock(&gRuleLock, FALSE, &LockState);

    for (i = 0; i < gRuleCount; i++)
    {
        const REDIRECT_RULE *Rule = &gRules[i];

        if (Rule->AddressFamily != PktInfo->AddressFamily)
        {
            continue;
        }

        if (Rule->Protocol != REDIRECT_PROTO_ANY && Rule->Protocol != PktInfo->Protocol)
        {
            continue;
        }

        if (Rule->OrigPort != 0 && Rule->OrigPort != PktInfo->DstPort)
        {
            continue;
        }

        if (!RedirectIpEqual(Rule->AddressFamily, &Rule->OrigIp, &PktInfo->DstIp))
        {
            continue;
        }

        *MatchedRule = *Rule;
        Found = TRUE;
        break;
    }

    NdisReleaseReadWriteLock(&gRuleLock, &LockState);
    return Found;
}

static
__inline
BOOLEAN
RedirectIsLocalRuleForPacket(
    IN const REDIRECT_RULE         *Rule,
    IN const PARSED_PACKET_INFO    *PktInfo
    )
{
    if ((Rule->Flags & REDIRECT_FLAG_LOCAL_LOOPBACK) != 0)
    {
        return TRUE;
    }

    // Auto-detect redirect to the host's own IP on this adapter
    if (RedirectIpEqual(PktInfo->AddressFamily, &Rule->NewIp, &PktInfo->SrcIp))
    {
        return TRUE;
    }

    return FALSE;
}

//
// Helper functions: NET_BUFFER inspection and flat buffer copy
//
static
BOOLEAN
RedirectPeekNbHeaders(
    IN  PNET_BUFFER             Nb,
    OUT PPARSED_PACKET_INFO     Info
    )
{
    UCHAR   PeekBuf[REDIRECT_PEEK_SIZE];
    ULONG   DataLen;
    ULONG   PeekLen;
    PUCHAR  HeaderPtr;

    DataLen = NET_BUFFER_DATA_LENGTH(Nb);
    if (DataLen < sizeof(ETH_HEADER) + sizeof(IPV4_HEADER) + sizeof(UDP_HEADER))
    {
        return FALSE;
    }

    PeekLen = (DataLen < REDIRECT_PEEK_SIZE) ? DataLen : REDIRECT_PEEK_SIZE;
    HeaderPtr = (PUCHAR)NdisGetDataBuffer(Nb, PeekLen, PeekBuf, 1, 0);
    if (HeaderPtr == NULL)
    {
        return FALSE;
    }

    return RedirectParsePacketHeaders(HeaderPtr, PeekLen, Info);
}

static
BOOLEAN
RedirectCopyNbToBuffer(
    IN  PNET_BUFFER     Nb,
    OUT PUCHAR          DstBuf,
    IN  ULONG           TotalLen
    )
{
    PMDL    CurrMdl;
    ULONG   MdlOffset;
    ULONG   Remaining = TotalLen;
    PUCHAR  DstPtr = DstBuf;

    CurrMdl = NET_BUFFER_CURRENT_MDL(Nb);
    MdlOffset = NET_BUFFER_CURRENT_MDL_OFFSET(Nb);

    while (Remaining > 0 && CurrMdl != NULL)
    {
        ULONG   MdlByteCount = MmGetMdlByteCount(CurrMdl);
        PUCHAR  SrcPtr;

        if (MdlOffset >= MdlByteCount)
        {
            MdlOffset -= MdlByteCount;
            CurrMdl = NDIS_MDL_LINKAGE(CurrMdl);
            continue;
        }

        SrcPtr = (PUCHAR)MmGetSystemAddressForMdlSafe(CurrMdl, LowPagePriority);
        if (SrcPtr == NULL)
        {
            return FALSE;
        }

        {
            ULONG Avail = MdlByteCount - MdlOffset;
            ULONG ToCopy = (Remaining < Avail) ? Remaining : Avail;

            NdisMoveMemory(DstPtr, SrcPtr + MdlOffset, ToCopy);
            DstPtr += ToCopy;
            Remaining -= ToCopy;
            MdlOffset = 0;
        }

        CurrMdl = NDIS_MDL_LINKAGE(CurrMdl);
    }

    return (Remaining == 0) ? TRUE : FALSE;
}

static
ULONG
RedirectGetLsoMss(
    IN PNET_BUFFER_LIST Nbl
    )
{
    NDIS_TCP_LARGE_SEND_OFFLOAD_NET_BUFFER_LIST_INFO LsoInfo;

    LsoInfo.Value = NET_BUFFER_LIST_INFO(Nbl, TcpLargeSendNetBufferListInfo);
    if (LsoInfo.Value == NULL)
    {
        return 0;
    }

    if (LsoInfo.Transmit.Type == NDIS_TCP_LARGE_SEND_OFFLOAD_V1_TYPE)
    {
        return LsoInfo.LsoV1Transmit.MSS;
    }
    else if (LsoInfo.Transmit.Type == NDIS_TCP_LARGE_SEND_OFFLOAD_V2_TYPE)
    {
        return LsoInfo.LsoV2Transmit.MSS;
    }

    return 0;
}

static
ULONG
RedirectResolveL4Length(
    IN const PARSED_PACKET_INFO    *PktInfo,
    IN ULONG                        FullBufLen
    )
{
    ULONG   MaxAvail;

    if (FullBufLen <= PktInfo->L4HeaderOffset)
    {
        return 0;
    }

    MaxAvail = FullBufLen - PktInfo->L4HeaderOffset;
    if (PktInfo->IpPayloadL4Len != 0 && PktInfo->IpPayloadL4Len <= MaxAvail)
    {
        return PktInfo->IpPayloadL4Len;
    }

    return MaxAvail;
}

static
VOID
RedirectUpdatePacketChecksums(
    IN OUT PUCHAR                   PacketBuf,
    IN     ULONG                    PacketLen,
    IN     const PARSED_PACKET_INFO *PktInfo,
    IN     BOOLEAN                  IsLso,
    IN     BOOLEAN                  KeepZeroUdpV4
    )
{
    PUCHAR  IpPtr = PacketBuf + PktInfo->IpHeaderOffset;
    PUCHAR  L4Ptr = PacketBuf + PktInfo->L4HeaderOffset;
    PUCHAR  SrcIpPtr;
    PUCHAR  DstIpPtr;
    ULONG   L4Len;

    if (PktInfo->AddressFamily == REDIRECT_AF_IPV4)
    {
        PIPV4_HEADER Ip4 = (PIPV4_HEADER)IpPtr;
        RedirectRecalcIpv4Checksum(Ip4, PktInfo->IpHeaderLength);
        SrcIpPtr = Ip4->SrcAddr;
        DstIpPtr = Ip4->DstAddr;
    }
    else
    {
        PIPV6_HEADER Ip6 = (PIPV6_HEADER)IpPtr;
        SrcIpPtr = Ip6->SrcAddr;
        DstIpPtr = Ip6->DstAddr;
    }

    L4Len = RedirectResolveL4Length(PktInfo, PacketLen);
    if (L4Len == 0)
    {
        return;
    }

    if (IsLso && PktInfo->Protocol == REDIRECT_PROTO_TCP)
    {
        PTCP_HEADER Tcp = (PTCP_HEADER)L4Ptr;
        USHORT      PseudoSum;

        PseudoSum = RedirectCalcPseudoHeaderSum(
                        PktInfo->AddressFamily,
                        PktInfo->Protocol,
                        SrcIpPtr,
                        DstIpPtr,
                        0,
                        FALSE);
        Tcp->Checksum = RtlUshortByteSwap(PseudoSum);
    }
    else
    {
        RedirectRecalcL4Checksum(
            PktInfo->AddressFamily,
            PktInfo->Protocol,
            SrcIpPtr,
            DstIpPtr,
            L4Ptr,
            L4Len,
            KeepZeroUdpV4);
    }
}

static
VOID
RedirectApplyOutboundRewrite(
    IN OUT PUCHAR                   PacketBuf,
    IN     ULONG                    PacketLen,
    IN     const PARSED_PACKET_INFO *PktInfo,
    IN     const REDIRECT_RULE      *Rule,
    IN     BOOLEAN                  IsLso,
    IN     BOOLEAN                  HadTxChecksumOffload,
    IN     BOOLEAN                  DispatchLevel
    )
{
    PETH_HEADER Eth = (PETH_HEADER)PacketBuf;
    PUCHAR      IpPtr = PacketBuf + PktInfo->IpHeaderOffset;
    PUCHAR      L4Ptr = PacketBuf + PktInfo->L4HeaderOffset;
    USHORT      EffectiveNewPort;

    if ((Rule->Flags & REDIRECT_FLAG_REWRITE_MAC) != 0)
    {
        NdisMoveMemory(Eth->DstMac, Rule->NewDstMac, ETH_ADDR_LEN);
    }

    if (PktInfo->AddressFamily == REDIRECT_AF_IPV4)
    {
        PIPV4_HEADER Ip4 = (PIPV4_HEADER)IpPtr;
        NdisMoveMemory(Ip4->DstAddr, Rule->NewIp.V4, 4);
    }
    else
    {
        PIPV6_HEADER Ip6 = (PIPV6_HEADER)IpPtr;
        NdisMoveMemory(Ip6->DstAddr, Rule->NewIp.V6, 16);
    }

    EffectiveNewPort = (Rule->NewPort != 0) ? Rule->NewPort : PktInfo->DstPort;

    if (PktInfo->Protocol == REDIRECT_PROTO_TCP)
    {
        PTCP_HEADER Tcp = (PTCP_HEADER)L4Ptr;
        Tcp->DstPort = EffectiveNewPort;
    }
    else
    {
        PUDP_HEADER Udp = (PUDP_HEADER)L4Ptr;
        Udp->DstPort = EffectiveNewPort;
    }

    RedirectUpsertExternalSession(PktInfo, Rule, EffectiveNewPort, DispatchLevel);

    RedirectUpdatePacketChecksums(
        PacketBuf,
        PacketLen,
        PktInfo,
        IsLso,
        HadTxChecksumOffload ? FALSE : TRUE);
}

static
VOID
RedirectApplyInboundRestore(
    IN OUT PUCHAR                   PacketBuf,
    IN     ULONG                    PacketLen,
    IN     const PARSED_PACKET_INFO *PktInfo,
    IN     const REDIRECT_IP_ADDR   *OrigSrcIp,
    IN     USHORT                   OrigSrcPort,
    IN     const UCHAR              *OrigSrcMac,
    IN     BOOLEAN                  RestoreSrcMac,
    IN     BOOLEAN                  SkipChecksumRecalc
    )
{
    PETH_HEADER Eth = (PETH_HEADER)PacketBuf;
    PUCHAR      IpPtr = PacketBuf + PktInfo->IpHeaderOffset;
    PUCHAR      L4Ptr = PacketBuf + PktInfo->L4HeaderOffset;

    if (RestoreSrcMac)
    {
        NdisMoveMemory(Eth->SrcMac, OrigSrcMac, ETH_ADDR_LEN);
    }

    if (PktInfo->AddressFamily == REDIRECT_AF_IPV4)
    {
        PIPV4_HEADER Ip4 = (PIPV4_HEADER)IpPtr;
        NdisMoveMemory(Ip4->SrcAddr, OrigSrcIp->V4, 4);
    }
    else
    {
        PIPV6_HEADER Ip6 = (PIPV6_HEADER)IpPtr;
        NdisMoveMemory(Ip6->SrcAddr, OrigSrcIp->V6, 16);
    }

    if (PktInfo->Protocol == REDIRECT_PROTO_TCP)
    {
        PTCP_HEADER Tcp = (PTCP_HEADER)L4Ptr;
        Tcp->SrcPort = OrigSrcPort;
    }
    else
    {
        PUDP_HEADER Udp = (PUDP_HEADER)L4Ptr;
        Udp->SrcPort = OrigSrcPort;
    }

    if (!SkipChecksumRecalc)
    {
        RedirectUpdatePacketChecksums(PacketBuf, PacketLen, PktInfo, FALSE, TRUE);
    }
}

//
// Helper functions: Local loopback receive NBL creation, LSO segmentation, async injection
//
static
PNET_BUFFER_LIST
RedirectWrapBufferAsReceiveNbl(
    IN PMS_FILTER   pFilter,
    IN PUCHAR       Buf,
    IN ULONG        DataLen
    )
{
    PMDL                Mdl;
    PNET_BUFFER         Nb;
    PNET_BUFFER_LIST    Nbl;

    Mdl = NdisAllocateMdl(pFilter->FilterHandle, Buf, DataLen);
    if (Mdl == NULL)
    {
        return NULL;
    }

    Nb = NdisAllocateNetBuffer(pFilter->RedirectNbPool, Mdl, 0, DataLen);
    if (Nb == NULL)
    {
        NdisFreeMdl(Mdl);
        return NULL;
    }

    Nbl = NdisAllocateNetBufferList(pFilter->RedirectNblPool, 0, 0);
    if (Nbl == NULL)
    {
        NdisFreeNetBuffer(Nb);
        NdisFreeMdl(Mdl);
        return NULL;
    }

    NET_BUFFER_NEXT_NB(Nb) = NULL;
    NET_BUFFER_LIST_FIRST_NB(Nbl) = Nb;
    NET_BUFFER_LIST_NEXT_NBL(Nbl) = NULL;
    NET_BUFFER_LIST_STATUS(Nbl) = NDIS_STATUS_SUCCESS;
    Nbl->SourceHandle = pFilter->FilterHandle;
    Nbl->ParentNetBufferList = NULL;

    return Nbl;
}

static
VOID
RedirectFixupIpLengthForLocalInject(
    IN OUT PUCHAR                   PacketBuf,
    IN     ULONG                    PacketLen,
    IN     const PARSED_PACKET_INFO *PktInfo
    )
{
    PUCHAR  IpPtr = PacketBuf + PktInfo->IpHeaderOffset;

    if (PktInfo->AddressFamily == REDIRECT_AF_IPV4)
    {
        PIPV4_HEADER Ip4 = (PIPV4_HEADER)IpPtr;
        if (Ip4->TotalLength == 0 && PacketLen > PktInfo->IpHeaderOffset)
        {
            Ip4->TotalLength = RtlUshortByteSwap((USHORT)(PacketLen - PktInfo->IpHeaderOffset));
        }
    }
    else
    {
        PIPV6_HEADER Ip6 = (PIPV6_HEADER)IpPtr;
        if (Ip6->PayloadLength == 0 &&
            PacketLen >= PktInfo->IpHeaderOffset + sizeof(IPV6_HEADER))
        {
            Ip6->PayloadLength = RtlUshortByteSwap(
                                     (USHORT)(PacketLen - PktInfo->IpHeaderOffset - sizeof(IPV6_HEADER)));
        }
    }
}

static
BOOLEAN
RedirectBuildLocalInjectNbls(
    IN  PMS_FILTER                  pFilter,
    IN  PUCHAR                      PacketBuf,
    IN  ULONG                       PacketLen,
    IN  const PARSED_PACKET_INFO   *PktInfo,
    IN  ULONG                       LsoMss,
    OUT PNET_BUFFER_LIST           *OutHead,
    OUT PNET_BUFFER_LIST           *OutTail,
    OUT PULONG                      OutCount,
    OUT PBOOLEAN                    PacketBufConsumed
    )
{
    PNET_BUFFER_LIST    Head = NULL;
    PNET_BUFFER_LIST    Tail = NULL;
    ULONG               Count = 0;

    *OutHead = NULL;
    *OutTail = NULL;
    *OutCount = 0;
    *PacketBufConsumed = FALSE;

    // If LSO TCP packet exceeds MSS, segment in software before receive indication
    if (LsoMss != 0 && PktInfo->Protocol == REDIRECT_PROTO_TCP)
    {
        PTCP_HEADER Tcp = (PTCP_HEADER)(PacketBuf + PktInfo->L4HeaderOffset);
        ULONG       TcpHdrLen = (ULONG)(Tcp->DataOffsetRes >> 4) * 4;
        ULONG       HdrTotalLen = PktInfo->L4HeaderOffset + TcpHdrLen;

        if (TcpHdrLen >= sizeof(TCP_HEADER) && HdrTotalLen <= PacketLen)
        {
            ULONG   PayloadLen = PacketLen - HdrTotalLen;
            ULONG   EffectiveMss = LsoMss;

            if (EffectiveMss == 0)
            {
                EffectiveMss = (PktInfo->AddressFamily == REDIRECT_AF_IPV6)
                                   ? REDIRECT_DEFAULT_MSS_V6
                                   : REDIRECT_DEFAULT_MSS_V4;
            }

            if (PayloadLen > EffectiveMss)
            {
                ULONG   BaseSeq = RtlUlongByteSwap(Tcp->SeqNum);
                USHORT  BaseIpId = 0;
                ULONG   Offset = 0;
                USHORT  SegIdx = 0;

                if (PktInfo->AddressFamily == REDIRECT_AF_IPV4)
                {
                    PIPV4_HEADER Ip4 = (PIPV4_HEADER)(PacketBuf + PktInfo->IpHeaderOffset);
                    BaseIpId = RtlUshortByteSwap(Ip4->Identification);
                }

                while (Offset < PayloadLen)
                {
                    ULONG               SegPayload = PayloadLen - Offset;
                    ULONG               SegLen;
                    PUCHAR              SegBuf;
                    PTCP_HEADER         SegTcp;
                    PARSED_PACKET_INFO  SegInfo;
                    PNET_BUFFER_LIST    SegNbl;

                    if (SegPayload > EffectiveMss)
                    {
                        SegPayload = EffectiveMss;
                    }

                    SegLen = HdrTotalLen + SegPayload;
                    SegBuf = (PUCHAR)NdisAllocateMemoryWithTagPriority(
                                         pFilter->FilterHandle,
                                         SegLen,
                                         FILTER_ALLOC_TAG,
                                         NormalPoolPriority);
                    if (SegBuf == NULL)
                    {
                        goto FailCleanup;
                    }

                    NdisMoveMemory(SegBuf, PacketBuf, HdrTotalLen);
                    NdisMoveMemory(SegBuf + HdrTotalLen, PacketBuf + HdrTotalLen + Offset, SegPayload);

                    SegTcp = (PTCP_HEADER)(SegBuf + PktInfo->L4HeaderOffset);
                    SegTcp->SeqNum = RtlUlongByteSwap(BaseSeq + Offset);
                    if (Offset > 0)
                    {
                        SegTcp->Flags &= (UCHAR)(~TCP_FLAG_CWR);
                    }
                    if (Offset + SegPayload < PayloadLen)
                    {
                        SegTcp->Flags &= (UCHAR)(~(TCP_FLAG_FIN | TCP_FLAG_PSH));
                    }

                    if (PktInfo->AddressFamily == REDIRECT_AF_IPV4)
                    {
                        PIPV4_HEADER SegIp4 = (PIPV4_HEADER)(SegBuf + PktInfo->IpHeaderOffset);
                        SegIp4->TotalLength = RtlUshortByteSwap((USHORT)(SegLen - PktInfo->IpHeaderOffset));
                        SegIp4->Identification = RtlUshortByteSwap((USHORT)(BaseIpId + SegIdx));
                    }
                    else
                    {
                        PIPV6_HEADER SegIp6 = (PIPV6_HEADER)(SegBuf + PktInfo->IpHeaderOffset);
                        SegIp6->PayloadLength = RtlUshortByteSwap(
                                                    (USHORT)(SegLen - PktInfo->IpHeaderOffset - sizeof(IPV6_HEADER)));
                    }

                    SegInfo = *PktInfo;
                    SegInfo.IpPayloadL4Len = TcpHdrLen + SegPayload;

                    RedirectUpdatePacketChecksums(SegBuf, SegLen, &SegInfo, FALSE, FALSE);

                    SegNbl = RedirectWrapBufferAsReceiveNbl(pFilter, SegBuf, SegLen);
                    if (SegNbl == NULL)
                    {
                        NdisFreeMemory(SegBuf, 0, 0);
                        goto FailCleanup;
                    }

                    if (Head == NULL)
                    {
                        Head = SegNbl;
                    }
                    else
                    {
                        NET_BUFFER_LIST_NEXT_NBL(Tail) = SegNbl;
                    }
                    Tail = SegNbl;
                    Count++;

                    Offset += SegPayload;
                    SegIdx++;
                }

                *OutHead = Head;
                *OutTail = Tail;
                *OutCount = Count;
                *PacketBufConsumed = FALSE; // Caller frees original large PacketBuf
                return TRUE;
            }
        }
    }

    // Standard single-packet receive injection
    {
        PARSED_PACKET_INFO  FixedInfo = *PktInfo;
        PNET_BUFFER_LIST    SingleNbl;

        RedirectFixupIpLengthForLocalInject(PacketBuf, PacketLen, PktInfo);
        if (FixedInfo.IpPayloadL4Len == 0 && PacketLen > FixedInfo.L4HeaderOffset)
        {
            FixedInfo.IpPayloadL4Len = PacketLen - FixedInfo.L4HeaderOffset;
        }

        RedirectUpdatePacketChecksums(PacketBuf, PacketLen, &FixedInfo, FALSE, FALSE);

        SingleNbl = RedirectWrapBufferAsReceiveNbl(pFilter, PacketBuf, PacketLen);
        if (SingleNbl == NULL)
        {
            return FALSE;
        }

        *OutHead = SingleNbl;
        *OutTail = SingleNbl;
        *OutCount = 1;
        *PacketBufConsumed = TRUE; // PacketBuf is now owned by SingleNbl
        return TRUE;
    }

FailCleanup:
    while (Head != NULL)
    {
        PNET_BUFFER_LIST Next = NET_BUFFER_LIST_NEXT_NBL(Head);
        NET_BUFFER_LIST_NEXT_NBL(Head) = NULL;
        RedirectFreeClonedNbl(Head);
        Head = Next;
    }
    return FALSE;
}

static
VOID
RedirectEnqueueInjectNbls(
    IN PMS_FILTER       pFilter,
    IN PNET_BUFFER_LIST Head,
    IN PNET_BUFFER_LIST Tail,
    IN ULONG            Count,
    IN BOOLEAN          DispatchLevel
    )
{
    if (Head == NULL || Count == 0)
    {
        return;
    }

    InterlockedExchangeAdd(&pFilter->PendingClonedReceives, (LONG)Count);

    FILTER_ACQUIRE_LOCK(&pFilter->InjectLock, DispatchLevel);

    if (pFilter->InjectHead == NULL)
    {
        pFilter->InjectHead = Head;
    }
    else
    {
        NET_BUFFER_LIST_NEXT_NBL(pFilter->InjectTail) = Head;
    }
    pFilter->InjectTail = Tail;
    pFilter->InjectCount += Count;

    FILTER_RELEASE_LOCK(&pFilter->InjectLock, DispatchLevel);

    KeInsertQueueDpc(&pFilter->InjectDpc, NULL, NULL);
}

VOID
RedirectInjectDpcRoutine(
    IN PKDPC    Dpc,
    IN PVOID    DeferredContext,
    IN PVOID    SystemArgument1,
    IN PVOID    SystemArgument2
    )
{
    PMS_FILTER          pFilter = (PMS_FILTER)DeferredContext;
    BOOLEAN             bTrue = TRUE;
    PNET_BUFFER_LIST    BatchHead;
    ULONG               BatchCount;
    BOOLEAN             IsRunning;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    for (;;)
    {
        FILTER_ACQUIRE_LOCK(&pFilter->InjectLock, bTrue);
        BatchHead = pFilter->InjectHead;
        BatchCount = pFilter->InjectCount;
        pFilter->InjectHead = NULL;
        pFilter->InjectTail = NULL;
        pFilter->InjectCount = 0;
        FILTER_RELEASE_LOCK(&pFilter->InjectLock, bTrue);

        if (BatchHead == NULL)
        {
            break;
        }

        FILTER_ACQUIRE_LOCK(&pFilter->Lock, bTrue);
        IsRunning = (pFilter->State == FilterRunning) ? TRUE : FALSE;
        FILTER_RELEASE_LOCK(&pFilter->Lock, bTrue);

        if (IsRunning)
        {
            NdisFIndicateReceiveNetBufferLists(
                pFilter->FilterHandle,
                BatchHead,
                NDIS_DEFAULT_PORT_NUMBER,
                BatchCount,
                NDIS_RECEIVE_FLAGS_DISPATCH_LEVEL);
        }
        else
        {
            PNET_BUFFER_LIST Curr = BatchHead;
            while (Curr != NULL)
            {
                PNET_BUFFER_LIST Next = NET_BUFFER_LIST_NEXT_NBL(Curr);
                NET_BUFFER_LIST_NEXT_NBL(Curr) = NULL;
                RedirectFreeClonedNbl(Curr);
                InterlockedDecrement(&pFilter->PendingClonedReceives);
                Curr = Next;
            }
        }
    }
}

static
VOID
RedirectRewriteLocalPacketHeaders(
    IN OUT PUCHAR                   PacketBuf,
    IN     const PARSED_PACKET_INFO *PktInfo,
    IN     const REDIRECT_IP_ADDR   *NewSrcIp,
    IN     const REDIRECT_IP_ADDR   *NewDstIp,
    IN     USHORT                   NewSrcPort,
    IN     USHORT                   NewDstPort
    )
{
    PETH_HEADER Eth = (PETH_HEADER)PacketBuf;
    PUCHAR      IpPtr = PacketBuf + PktInfo->IpHeaderOffset;
    PUCHAR      L4Ptr = PacketBuf + PktInfo->L4HeaderOffset;

    // Swap Src/Dst MAC so the packet is addressed to this local NIC
    NdisMoveMemory(Eth->DstMac, PktInfo->SrcMac, ETH_ADDR_LEN);
    NdisMoveMemory(Eth->SrcMac, PktInfo->DstMac, ETH_ADDR_LEN);

    if (PktInfo->AddressFamily == REDIRECT_AF_IPV4)
    {
        PIPV4_HEADER Ip4 = (PIPV4_HEADER)IpPtr;
        NdisMoveMemory(Ip4->SrcAddr, NewSrcIp->V4, 4);
        NdisMoveMemory(Ip4->DstAddr, NewDstIp->V4, 4);
    }
    else
    {
        PIPV6_HEADER Ip6 = (PIPV6_HEADER)IpPtr;
        NdisMoveMemory(Ip6->SrcAddr, NewSrcIp->V6, 16);
        NdisMoveMemory(Ip6->DstAddr, NewDstIp->V6, 16);
    }

    if (PktInfo->Protocol == REDIRECT_PROTO_TCP)
    {
        PTCP_HEADER Tcp = (PTCP_HEADER)L4Ptr;
        Tcp->SrcPort = NewSrcPort;
        Tcp->DstPort = NewDstPort;
    }
    else
    {
        PUDP_HEADER Udp = (PUDP_HEADER)L4Ptr;
        Udp->SrcPort = NewSrcPort;
        Udp->DstPort = NewDstPort;
    }
}

//
// Public lifecycle APIs
//
VOID
RedirectGlobalInit(
    VOID
    )
{
    ULONG i;

    NdisInitializeReadWriteLock(&gRuleLock);
    gRuleCount = 0;
    gNextRuleId = 1;
    NdisZeroMemory(gRules, sizeof(gRules));

    FILTER_INIT_LOCK(&gSessionLock);
    InitializeListHead(&gSessionLru);
    for (i = 0; i < REDIRECT_SESSION_BUCKETS; i++)
    {
        InitializeListHead(&gSessionBuckets[i]);
    }
    gSessionCount = 0;

    gRedirectInitialized = TRUE;
}

VOID
RedirectGlobalCleanup(
    VOID
    )
{
    if (!gRedirectInitialized)
    {
        return;
    }

    RedirectPurgeSessionsByRuleId(0, TRUE);
    FILTER_FREE_LOCK(&gSessionLock);
    gRedirectInitialized = FALSE;
}

NDIS_STATUS
RedirectAttachFilter(
    IN PMS_FILTER   pFilter
    )
{
    NET_BUFFER_LIST_POOL_PARAMETERS NblPoolParams;
    NET_BUFFER_POOL_PARAMETERS      NbPoolParams;

    NdisZeroMemory(&NblPoolParams, sizeof(NblPoolParams));
    NblPoolParams.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
    NblPoolParams.Header.Revision = NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
    NblPoolParams.Header.Size = sizeof(NET_BUFFER_LIST_POOL_PARAMETERS);
    NblPoolParams.ProtocolId = NDIS_PROTOCOL_ID_DEFAULT;
    NblPoolParams.fAllocateNetBuffer = FALSE;
    NblPoolParams.ContextSize = 0;
    NblPoolParams.PoolTag = FILTER_ALLOC_TAG;
    NblPoolParams.DataSize = 0;

    pFilter->RedirectNblPool = NdisAllocateNetBufferListPool(
                                   pFilter->FilterHandle,
                                   &NblPoolParams);
    if (pFilter->RedirectNblPool == NULL)
    {
        return NDIS_STATUS_RESOURCES;
    }

    NdisZeroMemory(&NbPoolParams, sizeof(NbPoolParams));
    NbPoolParams.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
    NbPoolParams.Header.Revision = NET_BUFFER_POOL_PARAMETERS_REVISION_1;
    NbPoolParams.Header.Size = sizeof(NET_BUFFER_POOL_PARAMETERS);
    NbPoolParams.PoolTag = FILTER_ALLOC_TAG;
    NbPoolParams.DataSize = 0;

    pFilter->RedirectNbPool = NdisAllocateNetBufferPool(
                                  pFilter->FilterHandle,
                                  &NbPoolParams);
    if (pFilter->RedirectNbPool == NULL)
    {
        NdisFreeNetBufferListPool(pFilter->RedirectNblPool);
        pFilter->RedirectNblPool = NULL;
        return NDIS_STATUS_RESOURCES;
    }

    FILTER_INIT_LOCK(&pFilter->InjectLock);
    KeInitializeDpc(&pFilter->InjectDpc, RedirectInjectDpcRoutine, pFilter);
    pFilter->InjectHead = NULL;
    pFilter->InjectTail = NULL;
    pFilter->InjectCount = 0;
    pFilter->PendingClonedSends = 0;
    pFilter->PendingClonedReceives = 0;

    return NDIS_STATUS_SUCCESS;
}

VOID
RedirectPauseFilter(
    IN PMS_FILTER   pFilter
    )
{
    BOOLEAN             bFalse = FALSE;
    PNET_BUFFER_LIST    Curr;

    // Ensure all queued/running inject DPCs have finished
    KeFlushQueuedDpcs();

    // Drain any leftover NBLs still in the inject queue
    FILTER_ACQUIRE_LOCK(&pFilter->InjectLock, bFalse);
    Curr = pFilter->InjectHead;
    pFilter->InjectHead = NULL;
    pFilter->InjectTail = NULL;
    pFilter->InjectCount = 0;
    FILTER_RELEASE_LOCK(&pFilter->InjectLock, bFalse);

    while (Curr != NULL)
    {
        PNET_BUFFER_LIST Next = NET_BUFFER_LIST_NEXT_NBL(Curr);
        NET_BUFFER_LIST_NEXT_NBL(Curr) = NULL;
        RedirectFreeClonedNbl(Curr);
        InterlockedDecrement(&pFilter->PendingClonedReceives);
        Curr = Next;
    }

    while ((InterlockedCompareExchange(&pFilter->PendingClonedSends, 0, 0) != 0) ||
           (InterlockedCompareExchange(&pFilter->PendingClonedReceives, 0, 0) != 0))
    {
        NdisMSleep(10000);
    }
}

VOID
RedirectDetachFilter(
    IN PMS_FILTER   pFilter
    )
{
    if (pFilter->RedirectNbPool != NULL)
    {
        FILTER_FREE_LOCK(&pFilter->InjectLock);
        NdisFreeNetBufferPool(pFilter->RedirectNbPool);
        pFilter->RedirectNbPool = NULL;
    }

    if (pFilter->RedirectNblPool != NULL)
    {
        NdisFreeNetBufferListPool(pFilter->RedirectNblPool);
        pFilter->RedirectNblPool = NULL;
    }
}

//
// Public control-plane APIs
//
NTSTATUS
RedirectAddRule(
    IN OUT PREDIRECT_RULE   Rule
    )
{
    LOCK_STATE      LockState;
    REDIRECT_RULE   Normalized;
    ULONG           i;
    NTSTATUS        Status = STATUS_SUCCESS;

    if (Rule->AddressFamily != REDIRECT_AF_IPV4 &&
        Rule->AddressFamily != REDIRECT_AF_IPV6)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (Rule->Protocol != REDIRECT_PROTO_ANY &&
        Rule->Protocol != REDIRECT_PROTO_TCP &&
        Rule->Protocol != REDIRECT_PROTO_UDP)
    {
        return STATUS_INVALID_PARAMETER;
    }

    NdisZeroMemory(&Normalized, sizeof(Normalized));
    Normalized.RuleId = Rule->RuleId;
    Normalized.AddressFamily = Rule->AddressFamily;
    Normalized.Protocol = Rule->Protocol;
    Normalized.Flags = (USHORT)(Rule->Flags & (REDIRECT_FLAG_REWRITE_MAC | REDIRECT_FLAG_LOCAL_LOOPBACK));
    RedirectCopyIp(Rule->AddressFamily, &Normalized.OrigIp, &Rule->OrigIp);
    Normalized.OrigPort = Rule->OrigPort;
    Normalized.NewPort = Rule->NewPort;
    RedirectCopyIp(Rule->AddressFamily, &Normalized.NewIp, &Rule->NewIp);
    if ((Normalized.Flags & REDIRECT_FLAG_REWRITE_MAC) != 0)
    {
        NdisMoveMemory(Normalized.NewDstMac, Rule->NewDstMac, ETH_ADDR_LEN);
    }

    NdisAcquireReadWriteLock(&gRuleLock, TRUE, &LockState);

    if (Normalized.RuleId == 0)
    {
        if (gNextRuleId == 0)
        {
            gNextRuleId = 1;
        }
        Normalized.RuleId = gNextRuleId++;
    }
    else
    {
        for (i = 0; i < gRuleCount; i++)
        {
            if (gRules[i].RuleId == Normalized.RuleId)
            {
                gRules[i] = Normalized;
                NdisReleaseReadWriteLock(&gRuleLock, &LockState);
                RedirectPurgeSessionsByRuleId(Normalized.RuleId, FALSE);
                *Rule = Normalized;
                return STATUS_SUCCESS;
            }
        }
        if (Normalized.RuleId >= gNextRuleId)
        {
            gNextRuleId = Normalized.RuleId + 1;
        }
    }

    if (gRuleCount >= MAX_REDIRECT_RULES)
    {
        Status = STATUS_INSUFFICIENT_RESOURCES;
    }
    else
    {
        gRules[gRuleCount++] = Normalized;
        *Rule = Normalized;
    }

    NdisReleaseReadWriteLock(&gRuleLock, &LockState);
    return Status;
}

NTSTATUS
RedirectDeleteRule(
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

    NdisAcquireReadWriteLock(&gRuleLock, TRUE, &LockState);

    for (i = 0; i < gRuleCount; i++)
    {
        if (gRules[i].RuleId == RuleId)
        {
            if (i + 1 < gRuleCount)
            {
                NdisMoveMemory(
                    &gRules[i],
                    &gRules[i + 1],
                    (gRuleCount - i - 1) * sizeof(REDIRECT_RULE));
            }
            gRuleCount--;
            Found = TRUE;
            break;
        }
    }

    NdisReleaseReadWriteLock(&gRuleLock, &LockState);

    if (!Found)
    {
        return STATUS_NOT_FOUND;
    }

    RedirectPurgeSessionsByRuleId(RuleId, FALSE);
    return STATUS_SUCCESS;
}

VOID
RedirectClearRules(
    VOID
    )
{
    LOCK_STATE  LockState;

    NdisAcquireReadWriteLock(&gRuleLock, TRUE, &LockState);
    gRuleCount = 0;
    NdisReleaseReadWriteLock(&gRuleLock, &LockState);

    RedirectPurgeSessionsByRuleId(0, TRUE);
}

NTSTATUS
RedirectListRules(
    OUT PREDIRECT_RULE  Buffer,
    IN  ULONG           BufferLength,
    OUT PULONG          BytesRequired
    )
{
    LOCK_STATE  LockState;
    ULONG       Needed;
    NTSTATUS    Status;

    NdisAcquireReadWriteLock(&gRuleLock, FALSE, &LockState);

    Needed = gRuleCount * sizeof(REDIRECT_RULE);
    *BytesRequired = Needed;

    if (Needed == 0)
    {
        Status = STATUS_SUCCESS;
    }
    else if (BufferLength < Needed)
    {
        Status = STATUS_BUFFER_TOO_SMALL;
    }
    else
    {
        NdisMoveMemory(Buffer, gRules, Needed);
        Status = STATUS_SUCCESS;
    }

    NdisReleaseReadWriteLock(&gRuleLock, &LockState);
    return Status;
}

//
// Public data-plane APIs
//
VOID
RedirectFreeClonedNbl(
    IN PNET_BUFFER_LIST ClonedNbl
    )
{
    PNET_BUFFER CurrNb;
    PNET_BUFFER NextNb;

    CurrNb = NET_BUFFER_LIST_FIRST_NB(ClonedNbl);
    while (CurrNb != NULL)
    {
        PMDL    Mdl;
        PVOID   Buf;

        NextNb = NET_BUFFER_NEXT_NB(CurrNb);
        Mdl = NET_BUFFER_FIRST_MDL(CurrNb);
        if (Mdl != NULL)
        {
            Buf = MmGetMdlVirtualAddress(Mdl);
            NdisFreeMdl(Mdl);
            if (Buf != NULL)
            {
                NdisFreeMemory(Buf, 0, 0);
            }
        }
        NdisFreeNetBuffer(CurrNb);
        CurrNb = NextNb;
    }

    NET_BUFFER_LIST_FIRST_NB(ClonedNbl) = NULL;
    NdisFreeNetBufferList(ClonedNbl);
}

static
REDIRECT_SEND_ACTION
RedirectProcessLocalLoopbackSendNbl(
    IN PMS_FILTER       pFilter,
    IN PNET_BUFFER_LIST OrigNbl,
    IN BOOLEAN          DispatchLevel
    )
{
    PNET_BUFFER         OrigNb;
    PNET_BUFFER_LIST    InjectHead = NULL;
    PNET_BUFFER_LIST    InjectTail = NULL;
    ULONG               InjectCount = 0;
    ULONG               LsoMss = RedirectGetLsoMss(OrigNbl);

    for (OrigNb = NET_BUFFER_LIST_FIRST_NB(OrigNbl);
         OrigNb != NULL;
         OrigNb = NET_BUFFER_NEXT_NB(OrigNb))
    {
        ULONG               DataLen = NET_BUFFER_DATA_LENGTH(OrigNb);
        PUCHAR              Buf;
        PARSED_PACKET_INFO  PktInfo;
        REDIRECT_IP_ADDR    OrigDstIp;
        REDIRECT_IP_ADDR    ClientIp;
        USHORT              OrigDstPort = 0;
        REDIRECT_RULE       Rule;
        PNET_BUFFER_LIST    NbHead = NULL;
        PNET_BUFFER_LIST    NbTail = NULL;
        ULONG               NbCount = 0;
        BOOLEAN             BufConsumed = FALSE;
        BOOLEAN             Handled = FALSE;

        if (DataLen == 0)
        {
            goto FailCleanup;
        }

        Buf = (PUCHAR)NdisAllocateMemoryWithTagPriority(
                          pFilter->FilterHandle,
                          DataLen,
                          FILTER_ALLOC_TAG,
                          NormalPoolPriority);
        if (Buf == NULL)
        {
            goto FailCleanup;
        }

        if (!RedirectCopyNbToBuffer(OrigNb, Buf, DataLen))
        {
            NdisFreeMemory(Buf, 0, 0);
            goto FailCleanup;
        }

        if (RedirectParsePacketHeaders(Buf, DataLen, &PktInfo))
        {
            // 1. Check local server reply first (Server -> Client)
            if (RedirectLookupLocalReplySession(
                    &PktInfo,
                    DispatchLevel,
                    &OrigDstIp,
                    &OrigDstPort,
                    &ClientIp))
            {
                RedirectRewriteLocalPacketHeaders(
                    Buf,
                    &PktInfo,
                    &OrigDstIp,
                    &ClientIp,
                    OrigDstPort,
                    PktInfo.DstPort);
                Handled = TRUE;
            }
            // 2. Check client outbound matching local rule (Client -> Server)
            else if (RedirectMatchOutboundRule(&PktInfo, &Rule) &&
                     RedirectIsLocalRuleForPacket(&Rule, &PktInfo))
            {
                USHORT EffectiveNewPort = (Rule.NewPort != 0) ? Rule.NewPort : PktInfo.DstPort;

                RedirectUpsertLocalSession(&PktInfo, &Rule, EffectiveNewPort, DispatchLevel);

                RedirectRewriteLocalPacketHeaders(
                    Buf,
                    &PktInfo,
                    &PktInfo.DstIp,
                    &Rule.NewIp,
                    PktInfo.SrcPort,
                    EffectiveNewPort);
                Handled = TRUE;
            }
        }

        if (!Handled)
        {
            NdisFreeMemory(Buf, 0, 0);
            continue;
        }

        if (!RedirectBuildLocalInjectNbls(
                 pFilter,
                 Buf,
                 DataLen,
                 &PktInfo,
                 LsoMss,
                 &NbHead,
                 &NbTail,
                 &NbCount,
                 &BufConsumed))
        {
            NdisFreeMemory(Buf, 0, 0);
            goto FailCleanup;
        }

        if (!BufConsumed)
        {
            NdisFreeMemory(Buf, 0, 0);
        }

        if (InjectHead == NULL)
        {
            InjectHead = NbHead;
        }
        else
        {
            NET_BUFFER_LIST_NEXT_NBL(InjectTail) = NbHead;
        }
        InjectTail = NbTail;
        InjectCount += NbCount;
    }

    if (InjectHead != NULL)
    {
        RedirectEnqueueInjectNbls(pFilter, InjectHead, InjectTail, InjectCount, DispatchLevel);
    }

    return RedirectSendLocalInjected;

FailCleanup:
    while (InjectHead != NULL)
    {
        PNET_BUFFER_LIST Next = NET_BUFFER_LIST_NEXT_NBL(InjectHead);
        NET_BUFFER_LIST_NEXT_NBL(InjectHead) = NULL;
        RedirectFreeClonedNbl(InjectHead);
        InjectHead = Next;
    }
    return RedirectSendFailed;
}

REDIRECT_SEND_ACTION
RedirectProcessSendNbl(
    IN  PMS_FILTER          pFilter,
    IN  PNET_BUFFER_LIST    OrigNbl,
    IN  BOOLEAN             DispatchLevel,
    OUT PNET_BUFFER_LIST   *OutNbl
    )
{
    PNET_BUFFER         OrigNb;
    PARSED_PACKET_INFO  PktInfo;
    REDIRECT_RULE       Rule;
    REDIRECT_IP_ADDR    TmpOrigIp;
    REDIRECT_IP_ADDR    TmpClientIp;
    USHORT              TmpPort;
    BOOLEAN             AnyExternalMatch = FALSE;
    BOOLEAN             AnyLocalMatch = FALSE;
    PNET_BUFFER_LIST    CloneNbl = NULL;
    PNET_BUFFER         FirstCloneNb = NULL;
    PNET_BUFFER         LastCloneNb = NULL;
    BOOLEAN             IsLso;
    BOOLEAN             HadTxCsumOffload;
    NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO TxCsum;

    *OutNbl = OrigNbl;

    if ((gRuleCount == 0 && gSessionCount == 0) ||
        pFilter->RedirectNblPool == NULL ||
        pFilter->RedirectNbPool == NULL)
    {
        return RedirectSendPassthrough;
    }

    // Fast path: inspect NBs to classify as passthrough, local loopback, or external DNAT
    for (OrigNb = NET_BUFFER_LIST_FIRST_NB(OrigNbl);
         OrigNb != NULL;
         OrigNb = NET_BUFFER_NEXT_NB(OrigNb))
    {
        if (!RedirectPeekNbHeaders(OrigNb, &PktInfo))
        {
            continue;
        }

        if (RedirectLookupLocalReplySession(
                &PktInfo,
                DispatchLevel,
                &TmpOrigIp,
                &TmpPort,
                &TmpClientIp))
        {
            AnyLocalMatch = TRUE;
            break;
        }

        if (gRuleCount > 0 && RedirectMatchOutboundRule(&PktInfo, &Rule))
        {
            if (RedirectIsLocalRuleForPacket(&Rule, &PktInfo))
            {
                AnyLocalMatch = TRUE;
                break;
            }
            AnyExternalMatch = TRUE;
            break;
        }
    }

    if (AnyLocalMatch)
    {
        return RedirectProcessLocalLoopbackSendNbl(pFilter, OrigNbl, DispatchLevel);
    }

    if (!AnyExternalMatch)
    {
        return RedirectSendPassthrough;
    }

    // External DNAT path: clone NBL and rewrite matching NBs safely
    CloneNbl = NdisAllocateNetBufferList(pFilter->RedirectNblPool, 0, 0);
    if (CloneNbl == NULL)
    {
        return RedirectSendFailed;
    }

    NdisCopySendNetBufferListInfo(CloneNbl, OrigNbl);

    IsLso = (RedirectGetLsoMss(OrigNbl) != 0) ? TRUE : FALSE;
    TxCsum.Value = NET_BUFFER_LIST_INFO(OrigNbl, TcpIpChecksumNetBufferListInfo);
    HadTxCsumOffload = (TxCsum.Transmit.IsIPv4 || TxCsum.Transmit.IsIPv6) ? TRUE : FALSE;

    if (!IsLso)
    {
        NET_BUFFER_LIST_INFO(CloneNbl, TcpIpChecksumNetBufferListInfo) = NULL;
    }

    for (OrigNb = NET_BUFFER_LIST_FIRST_NB(OrigNbl);
         OrigNb != NULL;
         OrigNb = NET_BUFFER_NEXT_NB(OrigNb))
    {
        ULONG       DataLen = NET_BUFFER_DATA_LENGTH(OrigNb);
        PUCHAR      Buf = NULL;
        PMDL        Mdl = NULL;
        PNET_BUFFER CloneNb = NULL;

        if (DataLen == 0)
        {
            goto FailCleanup;
        }

        Buf = (PUCHAR)NdisAllocateMemoryWithTagPriority(
                          pFilter->FilterHandle,
                          DataLen,
                          FILTER_ALLOC_TAG,
                          NormalPoolPriority);
        if (Buf == NULL)
        {
            goto FailCleanup;
        }

        if (!RedirectCopyNbToBuffer(OrigNb, Buf, DataLen))
        {
            NdisFreeMemory(Buf, 0, 0);
            goto FailCleanup;
        }

        if (RedirectParsePacketHeaders(Buf, DataLen, &PktInfo))
        {
            if (RedirectMatchOutboundRule(&PktInfo, &Rule))
            {
                RedirectApplyOutboundRewrite(
                    Buf,
                    DataLen,
                    &PktInfo,
                    &Rule,
                    IsLso,
                    HadTxCsumOffload,
                    DispatchLevel);
            }
            else if (!IsLso && HadTxCsumOffload)
            {
                RedirectUpdatePacketChecksums(Buf, DataLen, &PktInfo, FALSE, FALSE);
            }
        }

        Mdl = NdisAllocateMdl(pFilter->FilterHandle, Buf, DataLen);
        if (Mdl == NULL)
        {
            NdisFreeMemory(Buf, 0, 0);
            goto FailCleanup;
        }

        CloneNb = NdisAllocateNetBuffer(pFilter->RedirectNbPool, Mdl, 0, DataLen);
        if (CloneNb == NULL)
        {
            NdisFreeMdl(Mdl);
            NdisFreeMemory(Buf, 0, 0);
            goto FailCleanup;
        }

        NET_BUFFER_NEXT_NB(CloneNb) = NULL;
        if (FirstCloneNb == NULL)
        {
            FirstCloneNb = CloneNb;
        }
        else
        {
            NET_BUFFER_NEXT_NB(LastCloneNb) = CloneNb;
        }
        LastCloneNb = CloneNb;
    }

    NET_BUFFER_LIST_FIRST_NB(CloneNbl) = FirstCloneNb;
    CloneNbl->SourceHandle = pFilter->FilterHandle;
    CloneNbl->ParentNetBufferList = OrigNbl;

    *OutNbl = CloneNbl;
    return RedirectSendCloned;

FailCleanup:
    NET_BUFFER_LIST_FIRST_NB(CloneNbl) = FirstCloneNb;
    RedirectFreeClonedNbl(CloneNbl);
    return RedirectSendFailed;
}

NDIS_STATUS
RedirectProcessReceiveNbl(
    IN  PMS_FILTER          pFilter,
    IN  PNET_BUFFER_LIST    OrigNbl,
    IN  BOOLEAN             DispatchLevel,
    OUT PNET_BUFFER_LIST   *ClonedNbl
    )
{
    PNET_BUFFER         OrigNb;
    PARSED_PACKET_INFO  PktInfo;
    REDIRECT_IP_ADDR    OrigSrcIp;
    USHORT              OrigSrcPort = 0;
    UCHAR               OrigSrcMac[ETH_ADDR_LEN];
    BOOLEAN             RestoreSrcMac = FALSE;
    ULONG               DataLen;
    PUCHAR              Buf = NULL;
    PNET_BUFFER_LIST    NewNbl = NULL;
    NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO RxCsum;
    BOOLEAN             RxCsumFailed;

    *ClonedNbl = NULL;

    if (gSessionCount == 0 || pFilter->RedirectNblPool == NULL || pFilter->RedirectNbPool == NULL)
    {
        return NDIS_STATUS_SUCCESS;
    }

    OrigNb = NET_BUFFER_LIST_FIRST_NB(OrigNbl);
    if (OrigNb == NULL)
    {
        return NDIS_STATUS_SUCCESS;
    }

    if (!RedirectPeekNbHeaders(OrigNb, &PktInfo))
    {
        return NDIS_STATUS_SUCCESS;
    }

    if (!RedirectLookupExternalSession(
             &PktInfo,
             DispatchLevel,
             &OrigSrcIp,
             &OrigSrcPort,
             OrigSrcMac,
             &RestoreSrcMac))
    {
        return NDIS_STATUS_SUCCESS;
    }

    DataLen = NET_BUFFER_DATA_LENGTH(OrigNb);
    if (DataLen == 0)
    {
        return NDIS_STATUS_SUCCESS;
    }

    Buf = (PUCHAR)NdisAllocateMemoryWithTagPriority(
                      pFilter->FilterHandle,
                      DataLen,
                      FILTER_ALLOC_TAG,
                      NormalPoolPriority);
    if (Buf == NULL)
    {
        return NDIS_STATUS_RESOURCES;
    }

    if (!RedirectCopyNbToBuffer(OrigNb, Buf, DataLen))
    {
        NdisFreeMemory(Buf, 0, 0);
        return NDIS_STATUS_RESOURCES;
    }

    RxCsum.Value = NET_BUFFER_LIST_INFO(OrigNbl, TcpIpChecksumNetBufferListInfo);
    RxCsumFailed = (RxCsum.Receive.IpChecksumFailed ||
                    RxCsum.Receive.TcpChecksumFailed ||
                    RxCsum.Receive.UdpChecksumFailed) ? TRUE : FALSE;

    if (RedirectParsePacketHeaders(Buf, DataLen, &PktInfo))
    {
        RedirectApplyInboundRestore(
            Buf,
            DataLen,
            &PktInfo,
            &OrigSrcIp,
            OrigSrcPort,
            OrigSrcMac,
            RestoreSrcMac,
            RxCsumFailed);
    }

    NewNbl = RedirectWrapBufferAsReceiveNbl(pFilter, Buf, DataLen);
    if (NewNbl == NULL)
    {
        NdisFreeMemory(Buf, 0, 0);
        return NDIS_STATUS_RESOURCES;
    }

    NdisCopyReceiveNetBufferListInfo(NewNbl, OrigNbl);
    if (!RxCsumFailed)
    {
        NET_BUFFER_LIST_INFO(NewNbl, TcpIpChecksumNetBufferListInfo) = NULL;
    }

    *ClonedNbl = NewNbl;
    return NDIS_STATUS_SUCCESS;
}

BOOLEAN
RedirectInjectLocalPacket(
    IN PMS_FILTER       pFilter,
    IN const UCHAR     *PacketData,
    IN ULONG            PacketLen,
    IN BOOLEAN          DispatchLevel
    )
{
    PUCHAR              Buf;
    PNET_BUFFER_LIST    Nbl;

    if (pFilter == NULL || PacketData == NULL || PacketLen == 0)
    {
        return FALSE;
    }

    Buf = (PUCHAR)NdisAllocateMemoryWithTagPriority(
                      pFilter->FilterHandle,
                      PacketLen,
                      FILTER_ALLOC_TAG,
                      NormalPoolPriority);
    if (Buf == NULL)
    {
        return FALSE;
    }

    NdisMoveMemory(Buf, PacketData, PacketLen);

    Nbl = RedirectWrapBufferAsReceiveNbl(pFilter, Buf, PacketLen);
    if (Nbl == NULL)
    {
        NdisFreeMemory(Buf, 0, 0);
        return FALSE;
    }

    NET_BUFFER_LIST_INFO(Nbl, TcpIpChecksumNetBufferListInfo) = NULL;
    RedirectEnqueueInjectNbls(pFilter, Nbl, Nbl, 1, DispatchLevel);
    return TRUE;
}
