#include "common.h"

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16
#define IMAGE_SIZEOF_SHORT_NAME 8
#define IMAGE_DOS_SIGNATURE 0x5A4D // MZ
#define IMAGE_NT_SIGNATURE 0x00004550 // PE00
#define IMAGE_NT_OPTIONAL_HDR32_MAGIC      0x10b
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC      0x20b
#define IMAGE_DATA_DIRECTORY_IMPORT 1
#define IMAGE_DATA_DIRECTORY_EXPORT 0
#define IMAGE_ORDINAL_FLAG64 0x8000000000000000
#define IMAGE_ORDINAL_FLAG32 0x80000000

#define IMAGE_ORDINAL64(Ordinal) (Ordinal & 0xffff)
#define IMAGE_ORDINAL32(Ordinal) (Ordinal & 0xffff)
#define IMAGE_SNAP_BY_ORDINAL64(Ordinal) ((Ordinal & IMAGE_ORDINAL_FLAG64) != 0)
#define IMAGE_SNAP_BY_ORDINAL32(Ordinal) ((Ordinal & IMAGE_ORDINAL_FLAG32) != 0)

namespace windows {
	typedef struct _image_dos_header {      // DOS .EXE header
		common::word   e_magic;                     // Magic number
		common::word   e_cblp;                      // Bytes on last page of file
		common::word   e_cp;                        // Pages in file
		common::word   e_crlc;                      // Relocations
		common::word   e_cparhdr;                   // Size of header in paragraphs
		common::word   e_minalloc;                  // Minimum extra paragraphs needed
		common::word   e_maxalloc;                  // Maximum extra paragraphs needed
		common::word   e_ss;                        // Initial (relative) SS value
		common::word   e_sp;                        // Initial SP value
		common::word   e_csum;                      // Checksum
		common::word   e_ip;                        // Initial IP value
		common::word   e_cs;                        // Initial (relative) CS value
		common::word   e_lfarlc;                    // File address of relocation table
		common::word   e_ovno;                      // Overlay number
		common::word   e_res[4];                    // Reserved words
		common::word   e_oemid;                     // OEM identifier (for e_oeminfo)
		common::word   e_oeminfo;                   // OEM information; e_oemid specific
		common::word   e_res2[10];                  // Reserved words
		common::dword   e_lfanew;                    // File address of new exe header
	} image_dos_header, *pimage_dos_header;

	typedef struct _image_file_header {
		common::word machine;
		common::word number_of_sections;
		common::dword timedate_stamp;
		common::dword pointer_to_symbol_table;
		common::dword number_of_symbols;
		common::word size_of_optional_header;
		common::word characteristics;
	} image_file_header, *pimage_file_header;

	typedef struct _image_data_directory {
		common::dword virtual_address;
		common::dword size;
	} image_data_directory, *pimage_data_directory;

	typedef struct _image_optional_header_32 {
		common::word magic;
		common::byte major_linker_version;
		common::byte minor_linker_version;
		common::dword size_of_code;
		common::dword size_of_initialized_data;
		common::dword size_of_uninitialized_data;
		common::dword address_of_entry_point;
		common::dword base_of_code;
		common::dword base_of_data;
		common::dword image_base;
		common::dword section_alignment;
		common::dword file_alignment;
		common::word major_operating_system_version;
		common::word minor_operating_system_version;
		common::word major_image_version;
		common::word minor_image_version;
		common::word major_subsystemversion;
		common::word minor_subsystemversion;
		common::dword win32_version_value;
		common::dword size_of_image;
		common::dword size_of_headers;
		common::dword checkSum;
		common::word subsystem;
		common::word dll_characteristics;
		common::dword size_of_stack_reserve;
		common::dword size_of_stack_commit;
		common::dword size_of_heap_reserve;
		common::dword size_of_heap_commit;
		common::dword loader_flags;
		common::dword number_of_rva_and_sizes;
		image_data_directory data_directory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
	} image_optional_header_32, *pimage_optional_header_32;

	typedef struct _image_optional_header_64 {
		common::word magic;
		common::byte major_linker_version;
		common::byte minor_linker_version;
		common::dword size_of_code;
		common::dword size_of_initialized_data;
		common::dword size_of_uninitialized_data;
		common::dword address_of_entry_point;
		common::dword base_of_code;
		common::dword base_of_data;
		common::qword image_base;
		common::dword section_alignment;
		common::dword file_alignment;
		common::word major_operating_system_version;
		common::word minor_operating_system_version;
		common::word major_image_version;
		common::word minor_image_version;
		common::word major_subsystemversion;
		common::word minor_subsystemversion;
		common::dword win32_version_value;
		common::dword size_of_image;
		common::dword size_of_headers;
		common::dword checkSum;
		common::word subsystem;
		common::word dll_characteristics;
		common::qword size_of_stack_reserve;
		common::qword size_of_stack_commit;
		common::qword size_of_heap_reserve;
		common::qword size_of_heap_commit;
		common::dword loader_flags;
		common::dword number_of_rva_and_sizes;
		image_data_directory data_directory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
	} image_optional_header_64, *pimage_optional_header_64;

	typedef struct _image_nt_header_32 {
		common::dword signature;
		image_file_header file_header;
		image_optional_header_32 optional_header;
	} image_nt_header_32, *pimage_nt_header_32;

	typedef struct _image_nt_header_64 {
		common::dword signature;
		image_file_header file_header;
		image_optional_header_64 optional_header;
	} image_nt_header_64, *pimage_nt_header_64;

	typedef struct _image_section_header {
		common::byte name[IMAGE_SIZEOF_SHORT_NAME];
		union {
			common::dword physical_address;
			common::dword virtual_size;
		} misc;
		common::dword virtual_address;
		common::dword size_of_raw_data;
		common::dword pointer_to_raw_data;
		common::dword pointer_to_relocations;
		common::dword pointer_to_linenumbers;
		common::word number_of_relocations;
		common::word number_of_linenumbers;
		common::dword characteristics;
	} image_section_header, *pimage_section_header;
	
	typedef struct _image_import_descriptor {
		union {
			common::dword   characteristics;            // 0 for terminating null import descriptor
			common::dword   original_first_thunk;         // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
		} DUMMYUNIONNAME;
		common::dword   time_date_stamp;                  // 0 if not bound,
		// -1 if bound, and real date\time stamp
		//     in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
		// O.W. date/time stamp of DLL bound to (Old BIND)

		common::dword   forwarder_chain;                 // -1 if no forwarders
		common::dword   name;
		common::dword   first_thunk;                     // RVA to IAT (if bound this IAT has actual addresses)
	} image_import_descriptor, *pimage_import_descriptor;

	typedef struct _image_export_directory {
		common::dword characteristics;
		common::dword time_date_stamp;
		common::word major_version;
		common::word minor_version;
		common::dword name;
		common::dword base;
		common::dword number_of_functions;
		common::dword number_of_names;
		common::dword address_of_functions;     // RVA from base of image
		common::dword address_of_names;         // RVA from base of image
		common::dword address_of_name_ordinals;  // RVA from base of image
	} image_export_directory, *pimage_export_directory;


	typedef struct _image_thunk_data32 {
		union {
			common::dword forwarder_string;      // PBYTE 
			common::dword function;             // PDWORD
			common::dword ordinal;
			common::dword address_of_data;        // PIMAGE_IMPORT_BY_NAME
		} u;
	} image_thunk_data32, *pimage_thunk_data32;

}
