/*++

Module Name:

    dns_spoof.h

Abstract:

    DNS spoofing engine for NDIS 6.0 LWF.
    Intercepts outbound UDP/53 DNS queries (A / AAAA) matching configured
    exact or wildcard rules and injects forged DNS responses locally.

--*/

#ifndef _DNS_SPOOF_H_
#define _DNS_SPOOF_H_

//
// Lifecycle
//
VOID
DnsSpoofGlobalInit(
    VOID
    );

VOID
DnsSpoofGlobalCleanup(
    VOID
    );

//
// Control plane (IOCTL handlers)
//
NTSTATUS
DnsSpoofAddRule(
    IN OUT PDNS_SPOOF_RULE  Rule
    );

NTSTATUS
DnsSpoofDeleteRule(
    IN ULONG                RuleId
    );

VOID
DnsSpoofClearRules(
    VOID
    );

NTSTATUS
DnsSpoofListRules(
    OUT PDNS_SPOOF_RULE     Buffer,
    IN  ULONG               BufferLength,
    OUT PULONG              BytesRequired
    );

//
// Data plane
// Returns TRUE if the outbound NBL was consumed and a forged DNS response
// was queued for local receive indication.
//
BOOLEAN
DnsSpoofProcessSendNbl(
    IN PMS_FILTER           pFilter,
    IN PNET_BUFFER_LIST     OrigNbl,
    IN BOOLEAN              DispatchLevel
    );

#endif // _DNS_SPOOF_H_
