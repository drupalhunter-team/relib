#include "disasm.h"

disasm::intel::intel(disasm::decode_type _dt) : dt(_dt) {};

disasm::intel::prefix::prefix(common::byte *_buffer, streamsize _size, decode_type _dt) :dt(_dt), decoded_prefixes(0) {
	offset = _buffer;
	size = 0;
	for (int i = 0, bool done = false; (i < _size) && (i <= intel::max_instruction_length); ++i, ++size) {
		switch (_buffer[i]) {
			case 0x40:
			case 0x41:
			case 0x42:
			case 0x43:
			case 0x44:
			case 0x45:
			case 0x46:
			case 0x47:
			case 0x48:
			case 0x49:
			case 0x4a:
			case 0x4b:
			case 0x4c:
			case 0x4d:
			case 0x4e:
			case 0x4f:
				if (dt == decode_64_bits) {
					decoded_prefixes |= REX_PRE;
					rex.w = _buffer[i] & 0x8;
					rex.r = _buffer[i] & 0x4;
					rex.x = _buffer[i] & 0x2;
					rex.b = _buffer[i] & 0x1;
				}
				else
					done = true;
				break;
			case 0xf0:
				decoded_prefixes |= LOCK_PRE;
				break;
			case 0xf2:
				decoded_prefixes |= REPNZ_PRE;
				break;
			case 0xf3:
				decoded_prefixes |= REP_PRE;
				break;
			case 0x2e:
				decoded_prefixes |= CS_PRE;
				break;
			case 0x36:
				decoded_prefixes |= SS_PRE;
				break;
			case 0x3e:
				decoded_prefixes |= DS_PRE;
				break;
			case 0x26:
				decoded_prefixes |= ES_PRE;
				break;
			case 0x64:
				decoded_prefixes |= FS_PRE;
				break;
			case 0x65:
				decoded_prefixes |= GS_PRE;
				break;
			case 0x66:
				decoded_prefixes |= OPSIZE_PRE;
				break;
			case 0x67:
				decoded_prefixes |= ADDRSIZE_PRE;
				break;
		}
		if (done)
			break;
	}
}

void disasm::intel::disasm_buffer(common::byte *buffer, streamsize size) {
	
}