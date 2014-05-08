#include "common.h"

common::iofile::iofile(const char *filename, std::ios_base::openmode open_mode = std::ios_base::in | std::ios_base::binary) {
	file = new std::fstream();
	file->open(filename, open_mode);
	if (!file->is_open()) {
		throw open_iofile_error();
		file->close();
	}
	file->seekg(0, file->end);
	len = file->tellg();
	file->seekg(0, file->beg);
	cur = 0;
	mode = open_mode;
}

void common::iofile::read(byte *buffer, std::streamsize size, std::streampos pos) {
	if (cur != pos)
		file->seekg(pos, file->beg);
	file->read(reinterpret_cast <char *>(buffer), size);
	if (file->gcount() != size) {
		delete[] buffer;
		throw read_iofile_error();
	}
}

char *common::iofile::read_asciiz(std::streampos pos) {
	unsigned buffer_size = 10;
	char *buffer = NULL;
	do {
		// don't like this (
		if (buffer)
			delete [] buffer;
		buffer = new char[buffer_size];
		read((byte *)buffer, buffer_size, pos);
		int check = check_asciiz(buffer, buffer_size);
		if (check == -2) {
			delete[] buffer;
			throw read_asciiz_iofile_error();
		}
		else if (check == 0)
			return buffer;
		buffer_size <<= 1;
	} while (true);
}

void common::iofile::write(common::byte *buffer, std::streamsize size, std::streampos pos) {
	if (!(mode & std::ios_base::out))
		throw write_iofile_error();
	if (cur != pos)
		file->seekg(pos, file->beg);
	file->write(reinterpret_cast<char *>(buffer), size);
}

common::iofile::~iofile() {
	file->close();
	delete file;
}

int common::check_asciiz(char *str, unsigned size) {
	unsigned i = 0;
	for (; i < size; ++i) {
		if (str[i] == '\0')
			break;
		else if (!(isalnum(str[i]) || ispunct(str[i]))) {
			return -2;
		}
	}
	if (i < size)
		return 0;
	return -1;
}