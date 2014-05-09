#ifndef _PE_H_
#define _PE_H_

#include <algorithm> 
#include "common.h"
#include "win.h"

namespace pe {
	
	class not_dos_error {};
	class not_pe_error {};
	class not_pe32_error {};
	class not_pe64_error {};
	class not_valid_va_error {};
	class not_valid_offset_error {};

	const common::dword FILE_ALIGNEMNT_HARDCODED_VALUE = 0x200;

	typedef struct _pe_section {
		char *name;
		common::dword va;
		common::dword virtual_size;
		common::dword offset;
		common::dword physical_size;
		common::dword flags;
	} pe_section, *ppe_section;

	typedef struct _pe_address {
		common::dword va;
		common::dword offset;
	} pe_address, *ppe_address;

	typedef struct _import_symbol {
		common::dword addres;
		common::word ordinal;
		char *name;
		char *dll_name;
		bool is_ordinal;
	} import_symbol, *pimport_symbol;

	typedef struct _import_module {
		char *name;
		std::vector <pimport_symbol> is;
	} import_module, *pimport_module;

	typedef struct _export_symbol {
		common::dword addres;
		common::word ordinal;
		char *name;
	} export_symbol, *pexport_symbol;

	common::dword adjust_file_alignment(common::dword, common::dword);
	common::dword adjust_section_alignment(common::dword, common::dword, common::dword);

	class pe32 {
	public:
		common::iofile file;
		windows::pimage_dos_header idh;
		windows::pimage_nt_header_32 inh;
		std::vector <ppe_section> vec_sh;
		std::vector <pimport_module> vec_im;
		std::vector <pexport_symbol> vec_ess;
		pe_address ep;
		pe32(const char *);
		ppe_section section_by_va(common::dword);
		ppe_section section_by_offset(common::dword);
		ppe_section section_by_name(const char *);
		common::dword offset_by_va(common::dword);
		common::dword va_by_offset(common::dword);
		pexport_symbol export_by_address(common::dword);
		pexport_symbol export_by_ordinal(common::word);
		pexport_symbol export_by_name(char *);
		pimport_symbol import_by_address(common::dword);
	};

	class pe64 {
		common::iofile file;
		windows::pimage_dos_header idh;
	public:
		pe64(const char *);
		pe64(pe32 &);
	};
}

#endif
