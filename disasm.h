#ifndef _DISASM_H_
#define _DISASM_H_

#include <cstdlib>
#include "common.h"

using namespace std;

namespace disasm {
	typedef enum {decode_32_bits, decode_64_bits} decode_type;
	class intel {
		static const int max_instruction_length = 15;
		decode_type dt;
		class prefix {
			// Legacy prefix
			static const common::dword LOCK_PRE = 1 << 0;
			static const common::dword REPNZ_PRE = 1 << 1;
			static const common::dword REP_PRE = 1 << 2;
			static const common::dword CS_PRE = 1 << 3;
			static const common::dword SS_PRE = 1 << 4;
			static const common::dword DS_PRE = 1 << 5;
			static const common::dword ES_PRE = 1 << 6;
			static const common::dword FS_PRE = 1 << 7;
			static const common::dword GS_PRE = 1 << 8;
			static const common::dword OPSIZE_PRE = 1 << 9;
			static const common::dword ADDRSIZE_PRE = 1 << 10;
			// REX prefix
			static const common::dword REX_PRE = 1 << 11;
			// TODO: VEX and mandatory prefixes

			common::dword decoded_prefixes;
			typedef struct _rex_prefix {
				bool w;
				bool r;
				bool x;
				bool b;
			} rex_prefix, *prex_prefix;
			rex_prefix rex;
			common::byte *offset;
			streamsize size;
			decode_type dt;
		public:
			prefix(common::byte *, streamsize, decode_type);
		};
	public:
		intel(decode_type);
		void disasm_buffer(common::byte *, streamsize);
	};
}

#endif