#ifndef _COMMON_H_
#define _COMMON_H_

#include <cstdlib>
#include <fstream>
#include <cstdint>
#include <vector>
#include <cctype>
#include <algorithm>

namespace common {
	typedef uint8_t byte;
	typedef uint16_t word;
	typedef uint32_t dword;
	typedef uint64_t qword;

	class open_iofile_error {};
	class read_iofile_error {};
	class write_iofile_error {};
	class read_asciiz_iofile_error {};

	class iofile {
		std::fstream *file;
		std::streampos cur;
		std::ios_base::openmode mode;
	public:
		std::streamsize len;
		iofile(const char *, std::ios_base::openmode);
		void read(byte *, std::streamsize, std::streampos);
		void write(byte *, std::streamsize, std::streampos);
		char *read_asciiz(std::streampos);
		~iofile();
	};

	int check_asciiz(char *, unsigned);
}
#endif