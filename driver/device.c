/*++
 *
 * The file contains the routines to create a device and handle ioctls
 *
-- */

#include "precomp.h"

NDIS_STATUS
FilterRegisterDevice(
    VOID
    )
{
    NDIS_STATUS            Status = NDIS_STATUS_SUCCESS;
    UNICODE_STRING         DeviceName;
    UNICODE_STRING         DeviceLinkUnicodeString;
    PDRIVER_DISPATCH       DispatchTable[IRP_MJ_MAXIMUM_FUNCTION+1];
    NDIS_DEVICE_OBJECT_ATTRIBUTES   DeviceAttribute;
    PFILTER_DEVICE_EXTENSION        FilterDeviceExtension;
    PDRIVER_OBJECT                  DriverObject;
   
    DEBUGP(DL_TRACE, ("==>FilterRegisterDevice\n"));
   
    
    NdisZeroMemory(DispatchTable, (IRP_MJ_MAXIMUM_FUNCTION+1) * sizeof(PDRIVER_DISPATCH));
    
    DispatchTable[IRP_MJ_CREATE] = FilterDispatch;
    DispatchTable[IRP_MJ_CLEANUP] = FilterDispatch;
    DispatchTable[IRP_MJ_CLOSE] = FilterDispatch;
    DispatchTable[IRP_MJ_DEVICE_CONTROL] = FilterDeviceIoControl;
    
    
    NdisInitUnicodeString(&DeviceName, NTDEVICE_STRING);
    NdisInitUnicodeString(&DeviceLinkUnicodeString, LINKNAME_STRING);
    
    //
    // Create a device object and register our dispatch handlers
    //
    NdisZeroMemory(&DeviceAttribute, sizeof(NDIS_DEVICE_OBJECT_ATTRIBUTES));
    
    DeviceAttribute.Header.Type = NDIS_OBJECT_TYPE_DEVICE_OBJECT_ATTRIBUTES;
    DeviceAttribute.Header.Revision = NDIS_DEVICE_OBJECT_ATTRIBUTES_REVISION_1;
    DeviceAttribute.Header.Size = sizeof(NDIS_DEVICE_OBJECT_ATTRIBUTES);
    
    DeviceAttribute.DeviceName = &DeviceName;
    DeviceAttribute.SymbolicName = &DeviceLinkUnicodeString;
    DeviceAttribute.MajorFunctions = &DispatchTable[0];
    DeviceAttribute.ExtensionSize = sizeof(FILTER_DEVICE_EXTENSION);
    
    Status = NdisRegisterDeviceEx(
                FilterDriverHandle,
                &DeviceAttribute,
                &DeviceObject,
                &NdisFilterDeviceHandle
                );
   
   
    if (Status == NDIS_STATUS_SUCCESS)
    {
        FilterDeviceExtension = NdisGetDeviceReservedExtension(DeviceObject);
   
        FilterDeviceExtension->Signature = 'FTDR';
        FilterDeviceExtension->Handle = FilterDriverHandle;

        //
        // Workaround NDIS bug
        //
        DriverObject = (PDRIVER_OBJECT)FilterDriverObject;
    }
              
        
    DEBUGP(DL_TRACE, ("<==PtRegisterDevice: %x\n", Status));
        
    return (Status);
        
}

VOID
FilterDeregisterDevice(
    IN VOID
    )

{
    if (NdisFilterDeviceHandle != NULL)
    {
        NdisDeregisterDeviceEx(NdisFilterDeviceHandle);
    }

    NdisFilterDeviceHandle = NULL;

}

NTSTATUS
FilterDispatch(
    IN PDEVICE_OBJECT       DeviceObject,
    IN PIRP                 Irp
    )
{
    PIO_STACK_LOCATION       IrpStack;
    NTSTATUS                 Status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(DeviceObject);

    IrpStack = IoGetCurrentIrpStackLocation(Irp);
    
    switch (IrpStack->MajorFunction)
    {
        case IRP_MJ_CREATE:
            break;

        case IRP_MJ_CLEANUP:
            break;

        case IRP_MJ_CLOSE:
            break;

        default:
            break;
    }

    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return Status;
}
                
NTSTATUS
FilterDeviceIoControl(
    IN PDEVICE_OBJECT        DeviceObject,
    IN PIRP                  Irp
    )
{
    PIO_STACK_LOCATION          IrpSp;
    NTSTATUS                    Status = STATUS_SUCCESS;
    PFILTER_DEVICE_EXTENSION    FilterDeviceExtension;
    PUCHAR                      InputBuffer;
    PUCHAR                      OutputBuffer;
    ULONG                       InputBufferLength, OutputBufferLength;
    PLIST_ENTRY                 Link;
    PUCHAR                      pInfo;
    ULONG                       InfoLength = 0;
    PMS_FILTER                  pFilter = NULL;
    BOOLEAN                     bFalse = FALSE;


    UNREFERENCED_PARAMETER(DeviceObject);


    IrpSp = IoGetCurrentIrpStackLocation(Irp);

    if (IrpSp->FileObject == NULL)
    {
        return(STATUS_UNSUCCESSFUL);
    }


    FilterDeviceExtension = (PFILTER_DEVICE_EXTENSION)NdisGetDeviceReservedExtension(DeviceObject);

    ASSERT(FilterDeviceExtension->Signature == 'FTDR');
    
    Irp->IoStatus.Information = 0;

    switch (IrpSp->Parameters.DeviceIoControl.IoControlCode)
    {

        case IOCTL_FILTER_RESTART_ALL:
            break;

        case IOCTL_FILTER_RESTART_ONE_INSTANCE:
            InputBuffer = OutputBuffer = (PUCHAR)Irp->AssociatedIrp.SystemBuffer;
            InputBufferLength = IrpSp->Parameters.DeviceIoControl.InputBufferLength;

            pFilter = filterFindFilterModule (InputBuffer, InputBufferLength);

            if (pFilter == NULL)
            {
                
                break;
            }

            NdisFRestartFilter(pFilter->FilterHandle);

            break;

        case IOCTL_FILTER_ENUERATE_ALL_INSTANCES:
            
            InputBuffer = OutputBuffer = (PUCHAR)Irp->AssociatedIrp.SystemBuffer;
            InputBufferLength = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
            OutputBufferLength = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;
            
            
            pInfo = OutputBuffer;
            
            FILTER_ACQUIRE_LOCK(&FilterListLock, bFalse);
            
            Link = FilterModuleList.Flink;
            
            while (Link != &FilterModuleList)
            {
                pFilter = CONTAINING_RECORD(Link, MS_FILTER, FilterModuleLink);

                
                InfoLength += (pFilter->FilterModuleName.Length + sizeof(USHORT));
                        
                if (InfoLength <= OutputBufferLength)
                {
                    *(PUSHORT)pInfo = pFilter->FilterModuleName.Length;
                    NdisMoveMemory(pInfo + sizeof(USHORT), 
                                   (PUCHAR)(pFilter->FilterModuleName.Buffer),
                                   pFilter->FilterModuleName.Length);
                            
                    pInfo += (pFilter->FilterModuleName.Length + sizeof(USHORT));
                }
                
                Link = Link->Flink;
            }
               
            FILTER_RELEASE_LOCK(&FilterListLock, bFalse);
            if (InfoLength <= OutputBufferLength)
            {
       
                Status = NDIS_STATUS_SUCCESS;
            }
            //
            // Buffer is small
            //
            else
            {
                Status = STATUS_BUFFER_TOO_SMALL;
            }
            break;

             
        case IOCTL_FILTER_ADD_REDIRECT_RULE:
            InputBuffer = OutputBuffer = (PUCHAR)Irp->AssociatedIrp.SystemBuffer;
            InputBufferLength = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
            OutputBufferLength = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;

            if (InputBuffer == NULL || InputBufferLength < sizeof(REDIRECT_RULE))
            {
                Status = STATUS_INVALID_PARAMETER;
                break;
            }

            {
                REDIRECT_RULE Rule;
                NdisMoveMemory(&Rule, InputBuffer, sizeof(REDIRECT_RULE));
                Status = RedirectAddRule(&Rule);
                if (NT_SUCCESS(Status) && OutputBufferLength >= sizeof(REDIRECT_RULE))
                {
                    NdisMoveMemory(OutputBuffer, &Rule, sizeof(REDIRECT_RULE));
                    InfoLength = sizeof(REDIRECT_RULE);
                }
            }
            break;

        case IOCTL_FILTER_DEL_REDIRECT_RULE:
            InputBuffer = (PUCHAR)Irp->AssociatedIrp.SystemBuffer;
            InputBufferLength = IrpSp->Parameters.DeviceIoControl.InputBufferLength;

            if (InputBuffer == NULL || InputBufferLength < sizeof(REDIRECT_DEL_RULE))
            {
                Status = STATUS_INVALID_PARAMETER;
                break;
            }

            Status = RedirectDeleteRule(((PREDIRECT_DEL_RULE)InputBuffer)->RuleId);
            break;

        case IOCTL_FILTER_CLEAR_REDIRECT_RULES:
            RedirectClearRules();
            Status = STATUS_SUCCESS;
            break;

        case IOCTL_FILTER_LIST_REDIRECT_RULES:
            OutputBuffer = (PUCHAR)Irp->AssociatedIrp.SystemBuffer;
            OutputBufferLength = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;
            {
                ULONG BytesRequired = 0;
                Status = RedirectListRules(
                             (PREDIRECT_RULE)OutputBuffer,
                             OutputBufferLength,
                             &BytesRequired);
                if (NT_SUCCESS(Status))
                {
                    InfoLength = BytesRequired;
                }
            }
            break;

        case IOCTL_FILTER_ADD_DNS_SPOOF_RULE:
            InputBuffer = OutputBuffer = (PUCHAR)Irp->AssociatedIrp.SystemBuffer;
            InputBufferLength = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
            OutputBufferLength = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;

            if (InputBuffer == NULL || InputBufferLength < sizeof(DNS_SPOOF_RULE))
            {
                Status = STATUS_INVALID_PARAMETER;
                break;
            }

            {
                DNS_SPOOF_RULE DnsRule;
                NdisMoveMemory(&DnsRule, InputBuffer, sizeof(DNS_SPOOF_RULE));
                Status = DnsSpoofAddRule(&DnsRule);
                if (NT_SUCCESS(Status) && OutputBufferLength >= sizeof(DNS_SPOOF_RULE))
                {
                    NdisMoveMemory(OutputBuffer, &DnsRule, sizeof(DNS_SPOOF_RULE));
                    InfoLength = sizeof(DNS_SPOOF_RULE);
                }
            }
            break;

        case IOCTL_FILTER_DEL_DNS_SPOOF_RULE:
            InputBuffer = (PUCHAR)Irp->AssociatedIrp.SystemBuffer;
            InputBufferLength = IrpSp->Parameters.DeviceIoControl.InputBufferLength;

            if (InputBuffer == NULL || InputBufferLength < sizeof(DNS_SPOOF_DEL_RULE))
            {
                Status = STATUS_INVALID_PARAMETER;
                break;
            }

            Status = DnsSpoofDeleteRule(((PDNS_SPOOF_DEL_RULE)InputBuffer)->RuleId);
            break;

        case IOCTL_FILTER_CLEAR_DNS_SPOOF_RULES:
            DnsSpoofClearRules();
            Status = STATUS_SUCCESS;
            break;

        case IOCTL_FILTER_LIST_DNS_SPOOF_RULES:
            OutputBuffer = (PUCHAR)Irp->AssociatedIrp.SystemBuffer;
            OutputBufferLength = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;
            {
                ULONG BytesRequired = 0;
                Status = DnsSpoofListRules(
                             (PDNS_SPOOF_RULE)OutputBuffer,
                             OutputBufferLength,
                             &BytesRequired);
                if (NT_SUCCESS(Status))
                {
                    InfoLength = BytesRequired;
                }
            }
            break;

        default:
            Status = STATUS_INVALID_DEVICE_REQUEST;
            break;
    }

    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = InfoLength;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return Status;
            

}


PMS_FILTER    
filterFindFilterModule(
    IN PUCHAR                   Buffer,
    IN ULONG                    BufferLength
    )
{

   PMS_FILTER              pFilter;
   PLIST_ENTRY             Link;
   BOOLEAN                  bFalse = FALSE;
   
   FILTER_ACQUIRE_LOCK(&FilterListLock, bFalse);
               
   Link = FilterModuleList.Flink;
               
   while (Link != &FilterModuleList)
   {
       pFilter = CONTAINING_RECORD(Link, MS_FILTER, FilterModuleLink);

       if (BufferLength >= pFilter->FilterModuleName.Length)
       {
           if (NdisEqualMemory(Buffer, pFilter->FilterModuleName.Buffer, pFilter->FilterModuleName.Length))
           {
               FILTER_RELEASE_LOCK(&FilterListLock, bFalse);
               return pFilter;
           }
       }
           
       Link = Link->Flink;
   }
   
   FILTER_RELEASE_LOCK(&FilterListLock, bFalse);
   return NULL;
}




