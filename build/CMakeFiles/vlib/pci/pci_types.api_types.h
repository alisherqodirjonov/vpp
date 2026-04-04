#ifndef included_pci_types_api_types_h
#define included_pci_types_api_types_h
#define VL_API_PCI_TYPES_API_VERSION_MAJOR 1
#define VL_API_PCI_TYPES_API_VERSION_MINOR 0
#define VL_API_PCI_TYPES_API_VERSION_PATCH 0
/* Imported API files */
typedef struct __attribute__ ((packed)) _vl_api_pci_address {
    u16 domain;
    u8 bus;
    u8 slot;
    u8 function;
} vl_api_pci_address_t;
#define VL_API_PCI_ADDRESS_IS_CONSTANT_SIZE (1)


#endif
