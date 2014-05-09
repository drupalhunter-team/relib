#include "pe.h"
#include <cstdlib>
#include <iostream>

int main(int argc, char *argv[]) {
	pe::pe32 *ob = new pe::pe32(argv[1]);
	/*
	for (unsigned i = 0; i < ob->vec_sh.size(); ++i) {
		std::cout << ob->vec_sh[i]->name << std::endl;
		std::cout << std::hex << ob->vec_sh[i]->physical_size << ' '<< ob->vec_sh[i]->offset << std::endl;
		std::cout << ob->vec_sh[i]->virtual_size << ' ' << ob->vec_sh[i]->va << std::endl;
	}
	for (unsigned i = 0; i < ob->vec_im.size(); ++i) {
		printf("%s\n", ob->vec_im[i]->name);
		for (unsigned j = 0; j < ob->vec_im[i]->is.size(); ++j) {
			printf("\t%x - %s - %x - %s\n", ob->vec_im[i]->is[j]->addres, ob->vec_im[i]->is[j]->is_ordinal ? "true" : "false", ob->vec_im[i]->is[j]->ordinal, ob->vec_im[i]->is[j]->name);
		}
	}
	for (unsigned i = 0; i < ob->vec_ess.size(); ++i)
		printf("%x - %s - %x\n", ob->vec_ess[i]->ordinal, ob->vec_ess[i]->name, ob->vec_ess[i]->addres);
	*/
	common::byte temp[80];
	ob->file.read(temp, 80, ob->ep.offset);
	/*
	for (int i = 0; i < 80; ++i)
		std::cout << std::hex << int(temp[i]) << ' ';
	std::cout << std::endl;
	*/
	return 0;
}
