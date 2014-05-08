#include "pe.h"

pe::pe32::pe32(const char *filename) : file(filename, std::ios_base::in | std::ios_base::binary) {
	idh = new windows::image_dos_header;
	file.read((common::byte *)idh, sizeof(windows::image_dos_header), 0);
	if (idh->e_magic != IMAGE_DOS_SIGNATURE) {
		throw not_dos_error();
	}
	inh = new windows::image_nt_header_32;
	file.read((common::byte *)inh, sizeof(windows::image_nt_header_32), idh->e_lfanew);
	if (inh->signature != IMAGE_NT_SIGNATURE) {
		throw not_pe_error();
	}
	if (inh->optional_header.magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
		throw not_pe32_error();
	}
	
	// parse sections
	vec_sh.resize(inh->file_header.number_of_sections);
	for (unsigned i = 0; i < vec_sh.size(); ++i) {
		windows::image_section_header cur_ish;
		file.read((common::byte *)&cur_ish, sizeof(windows::image_section_header),
			idh->e_lfanew + sizeof(windows::image_nt_header_32) + i * sizeof(windows::image_section_header));
		vec_sh[i] = new pe_section();
		unsigned name_len = ((cur_ish.name[7] == 0) ? strlen((char *)cur_ish.name) : 9) + 1;
		vec_sh[i]->name = new char[name_len];
		memcpy(vec_sh[i]->name, cur_ish.name, name_len);
		vec_sh[i]->name[name_len - 1] = '\0';
		vec_sh[i]->physical_size = cur_ish.size_of_raw_data;
		vec_sh[i]->offset = adjust_file_alignment(cur_ish.pointer_to_raw_data, inh->optional_header.file_alignment);
		vec_sh[i]->virtual_size = cur_ish.misc.virtual_size;
		vec_sh[i]->va = adjust_section_alignment(cur_ish.virtual_address,
			inh->optional_header.file_alignment, inh->optional_header.section_alignment);
		if (i > 0) {
			if ((vec_sh[i]->va > vec_sh[i - 1]->va) &&
				(vec_sh[i - 1]->va + vec_sh[i - 1]->virtual_size > vec_sh[i]->va)) {
				vec_sh[i - 1]->virtual_size = vec_sh[i]->va - vec_sh[i - 1]->va;
			}
		}
		vec_sh[i]->flags = cur_ish.characteristics;
	}
	
	//parse entry point
	ep.va = inh->optional_header.address_of_entry_point;
	ep.offset = offset_by_va(ep.va);
	
	//parse import table
	common::dword import_va = inh->optional_header.data_directory[IMAGE_DATA_DIRECTORY_IMPORT].virtual_address;
	common::dword import_size = inh->optional_header.data_directory[IMAGE_DATA_DIRECTORY_IMPORT].size;
	windows::pimage_import_descriptor iat =
		new windows::image_import_descriptor[import_size / sizeof(windows::image_import_descriptor)];
	vec_im.clear();
	for (unsigned i = 0; i < import_size / sizeof(windows::image_import_descriptor); ++i,
		import_va += sizeof(windows::image_import_descriptor)) {
		file.read((common::byte *)&iat[i], sizeof(windows::image_import_descriptor), offset_by_va(import_va));
		if (*(common::qword *)&iat[i] == (common::qword)0) {
			break;
		}
		pe::pimport_module cur_im = new pe::import_module;
		char *dll_name = file.read_asciiz(offset_by_va(iat[i].name));
		cur_im->name = dll_name;
		windows::pimage_thunk_data32 name_thunk = new windows::image_thunk_data32;
		common::dword offset_name_thunk = offset_by_va(iat[i].DUMMYUNIONNAME.characteristics == 0 ?
			iat[i].first_thunk : iat[i].DUMMYUNIONNAME.characteristics);
		windows::pimage_thunk_data32 address_thunk = new windows::image_thunk_data32;
		common::dword offset_address_thunk = offset_by_va(iat[i].first_thunk);
		common::dword addr = iat[i].first_thunk + inh->optional_header.image_base;
		do {
			file.read((common::byte *)name_thunk, sizeof(windows::image_thunk_data32), offset_name_thunk);
			file.read((common::byte *)address_thunk, sizeof(windows::image_thunk_data32), offset_address_thunk);
			char *func_name;
			common::word hint;
			bool is_ordinal = false;
			if (!name_thunk->u.address_of_data) {
				break;
			}
			pimport_symbol cur_sym = new import_symbol;
			if (name_thunk->u.ordinal & IMAGE_ORDINAL_FLAG32) {
				is_ordinal = true;
				hint = IMAGE_ORDINAL32(name_thunk->u.ordinal);
				func_name = new char[10];
				memcpy(func_name, "undefined", 10);
			}
			else {
				file.read((common::byte *)&hint, sizeof(common::word), offset_by_va(name_thunk->u.address_of_data));
				func_name = file.read_asciiz(offset_by_va(name_thunk->u.address_of_data + sizeof(common::word)));
			}
			offset_name_thunk += sizeof(windows::image_thunk_data32);
			offset_address_thunk += sizeof(windows::image_thunk_data32);
			addr += sizeof(windows::image_thunk_data32);
			cur_sym->addres = addr;
			cur_sym->is_ordinal = is_ordinal;
			cur_sym->ordinal = hint;
			cur_sym->name = func_name;
			cur_sym->dll_name = dll_name;
			cur_im->is.push_back(cur_sym);
		} while (true);
		vec_im.push_back(cur_im);
	}
	delete[] iat;
	// TODO: parse bound import and delayed imports

	// parse export table
	common::dword export_va = inh->optional_header.data_directory[IMAGE_DATA_DIRECTORY_EXPORT].virtual_address;
	common::dword export_size = inh->optional_header.data_directory[IMAGE_DATA_DIRECTORY_EXPORT].size;
	windows::image_export_directory et;
	file.read((common::byte *)&et, sizeof(windows::image_export_directory), offset_by_va(export_va));
	vec_ess.clear();
	for (unsigned i = 0; i < et.number_of_names; ++i) {
		pexport_symbol cur_sym = new export_symbol;
		common::dword name_addr;
		file.read((common::byte *)&name_addr, sizeof(common::dword), offset_by_va(et.address_of_names + i * sizeof(common::dword)));
		char *func_name = file.read_asciiz(offset_by_va(name_addr));
		common::word ordinal;
		file.read((common::byte *)&ordinal, sizeof(common::word),
			offset_by_va(et.address_of_name_ordinals + i * sizeof(common::word)));
		ordinal += et.base;
		common::dword addr;
		file.read((common::byte *)&addr, sizeof(common::dword),
			offset_by_va(et.address_of_functions + (int)ordinal * sizeof(common::dword)));
		addr += inh->optional_header.image_base;
		cur_sym->addres = addr;
		cur_sym->ordinal = ordinal;
		cur_sym->name = func_name;
		vec_ess.push_back(cur_sym);
	}
}
	
common::dword pe::adjust_file_alignment(common::dword val, common::dword align) {
	if (align < FILE_ALIGNEMNT_HARDCODED_VALUE)
		return val;
	return (val / 0x200) * 0x200;
}

common::dword pe::adjust_section_alignment(common::dword val, common::dword file_align, common::dword sec_align) {
	if (sec_align < 0x1000) {
		sec_align = file_align;
	}
	else {
		if (sec_align < 0x80)
			sec_align = 0x80;
	}
	if ((sec_align > 0) && (val % sec_align > 0))
		return sec_align * (val / sec_align);
	return val;
}


pe::ppe_section pe::pe32::section_by_va(common::dword va) {
	for (unsigned i = 0; i < vec_sh.size(); ++i) {
		if ((va >= vec_sh[i]->va) && (va <= vec_sh[i]->va + vec_sh[i]->virtual_size))
			return vec_sh[i];
	}
	throw not_valid_va_error();
}

pe::ppe_section pe::pe32::section_by_offset(common::dword offset) {
	for (unsigned i = 0; i < vec_sh.size(); ++i) {
		if ((offset >= vec_sh[i]->offset) && (offset <= vec_sh[i]->offset + vec_sh[i]->virtual_size))
			return vec_sh[i];
	}
	throw not_valid_offset_error();
}

pe::ppe_section pe::pe32::section_by_name(const char *name) {
	for (unsigned i = 0; i < vec_sh.size(); ++i) {
		if (strcmp(vec_sh[i]->name, name) == 0)
			return vec_sh[i];
	}
	return NULL;
}

common::dword pe::pe32::offset_by_va(common::dword va) {
	ppe_section cur_sec = section_by_va(va);
	common::dword delta = va - cur_sec->va;
	common::dword raw_offset = cur_sec->offset + delta;
	if (raw_offset > file.len)
		throw not_valid_va_error();
	return raw_offset;
}

common::dword pe::pe32::va_by_offset(common::dword offset) {
	ppe_section cur_sec = section_by_offset(offset);
	common::dword delta = offset - cur_sec->offset;
	if (delta > cur_sec->physical_size || delta > cur_sec->virtual_size)
		throw not_valid_offset_error();
	common::dword va = cur_sec->va + delta;
	return va;
}

pe::pexport_symbol pe::pe32::export_by_address(common::dword va) {
	for (unsigned i = 0; i < vec_ess.size(); ++i) {
		if (va == vec_ess[i]->addres)
			return vec_ess[i];
	}
	return NULL;
}

pe::pexport_symbol pe::pe32::export_by_ordinal(common::word ordinal) {
	for (unsigned i = 0; i < vec_ess.size(); ++i) {
		if (ordinal == vec_ess[i]->ordinal)
			return vec_ess[i];
	}
	return NULL;
}

pe::pexport_symbol pe::pe32::export_by_name(char *name) {
	for (unsigned i = 0; i < vec_ess.size(); ++i) {
		if (!strcmp(name, vec_ess[i]->name))
			return vec_ess[i];
	}
	return NULL;
}

pe::pimport_symbol pe::pe32::import_by_address(common::dword va) {
	for (unsigned i = 0; i < vec_im.size(); ++i) {
		for (unsigned j = 0; j < vec_im[i]->is.size(); ++j) {
			if (va == vec_im[i]->is[j]->addres)
				return vec_im[i]->is[j];
		}
	}
	return NULL;
}