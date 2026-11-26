/*++

Module Name:

    redirect.h

Abstract:

    IPv4/IPv6 IP address and port redirection engine for NDIS LWF.

--*/

#ifndef _REDIRECT_H_
#define _REDIRECT_H_

typedef enum _REDIRECT_SEND_ACTION
{
    RedirectSendPassthrough = 0,
    RedirectSendCloned,
    RedirectSendLocalInjected,
    RedirectSendFailed
} REDIRECT_SEND_ACTION;

//
// Lifecycle
//
VOID
RedirectGlobalInit(
    VOID
    );

VOID
RedirectGlobalCleanup(
    VOID
    );

NDIS_STATUS
RedirectAttachFilter(
    IN PMS_FILTER       pFilter
    );

VOID
RedirectPauseFilter(
    IN PMS_FILTER       pFilter
    );

VOID
RedirectDetachFilter(
    IN PMS_FILTER       pFilter
    );

//
// Control plane (IOCTL handlers)
//
NTSTATUS
RedirectAddRule(
    IN OUT PREDIRECT_RULE   Rule
    );

NTSTATUS
RedirectDeleteRule(
    IN ULONG                RuleId
    );

VOID
RedirectClearRules(
    VOID
    );

NTSTATUS
RedirectListRules(
    OUT PREDIRECT_RULE      Buffer,
    IN  ULONG               BufferLength,
    OUT PULONG              BytesRequired
    );

//
// Data plane
//
REDIRECT_SEND_ACTION
RedirectProcessSendNbl(
    IN  PMS_FILTER          pFilter,
    IN  PNET_BUFFER_LIST    OrigNbl,
    IN  BOOLEAN             DispatchLevel,
    OUT PNET_BUFFER_LIST   *OutNbl
    );

NDIS_STATUS
RedirectProcessReceiveNbl(
    IN  PMS_FILTER          pFilter,
    IN  PNET_BUFFER_LIST    OrigNbl,
    IN  BOOLEAN             DispatchLevel,
    OUT PNET_BUFFER_LIST   *ClonedNbl
    );

VOID
RedirectFreeClonedNbl(
    IN PNET_BUFFER_LIST     ClonedNbl
    );

BOOLEAN
RedirectInjectLocalPacket(
    IN PMS_FILTER           pFilter,
    IN const UCHAR         *PacketData,
    IN ULONG                PacketLen,
    IN BOOLEAN              DispatchLevel
    );

#endif // _REDIRECT_H_
