#include "signature.h"
#include <ctype.h>
#include <map>

std::vector<uint8_t> g_hash_vals;
std::vector<hsig_t> g_hstrSignatures;
std::vector<sstring_t> g_hstr_strs;
uint32_t g_CurrentThreatID;
int32_t g_CurrentSigID = 0;

std::vector<uint8_t> g_sstrs;

struct global_database {
	std::vector<nid_entry_t> nid_rec;
	std::vector<nid64_entry_t> nid64_rec;
	std::vector<snid_entry_t> snid_rec;

	std::vector<staticrec_t> static_rec;
	std::vector<kcrce_t> pestatic_rec;
	std::vector<peemusig_t> peemu_rec;

	std::vector<pcode_virrec> pcode_rec;
}g_db;

extern std::vector<t_full_threat_record> g_full_threats;
std::vector<bootrecord_t> g_bsigs;
std::vector<simple_rec_ex> g_nsrs;
std::vector<simple_rec> g_srs;
std::vector<poly_vir> g_polyVirSignatures;
std::map<uint64_t, PCodeValidatorSig_t> g_pcode_sigs;

std::string get_threat_name(uint32_t threat_index) {
	auto info = std::lower_bound(g_full_threats.begin(),
		g_full_threats.end(), threat_index,
		[](const t_full_threat_record& info, uint32_t threat_index) {
			return info.threat_id < threat_index;
		});

	if (info == g_full_threats.end())
		return "";
	return info->name;
}

void hex2str(uint8_t* input, uint16_t input_len, char* output) {
	const char* hexEncode = "0123456789ABCDEF";
	int i = 0, j = 0;
	for (i = 0; i < input_len; i++)
	{
		output[j++] = hexEncode[(input[i] >> 4) & 0xF];
		output[j++] = hexEncode[input[i] & 0xF];
	}
}

uint32_t RemoveRecordName(signature_type RecordType, unsigned int& RecordSize, uint8_t* Record)
{
	switch (RecordType)
	{
	case SIGNATURE_TYPE_PEHSTR:
	case SIGNATURE_TYPE_PEHSTR_EXT:
	case SIGNATURE_TYPE_PEHSTR_EXT2:
	case SIGNATURE_TYPE_ELFHSTR_EXT:
	case SIGNATURE_TYPE_MACHOHSTR_EXT:
	case SIGNATURE_TYPE_DOSHSTR_EXT:
	case SIGNATURE_TYPE_MACROHSTR_EXT:
	case SIGNATURE_TYPE_DEXHSTR_EXT:
	case SIGNATURE_TYPE_JAVAHSTR_EXT:
	case SIGNATURE_TYPE_ARHSTR_EXT:
	case SIGNATURE_TYPE_SWFHSTR_EXT:
	case SIGNATURE_TYPE_AUTOITHSTR_EXT:
	case SIGNATURE_TYPE_INNOHSTR_EXT:
	case SIGNATURE_TYPE_CMDHSTR_EXT:
	{
		auto i = 7;
		if (RecordSize <= 7)
			return 0xB;

		if (!Record[6])//不为0时表示有name
			return 0x490;

		do {
			if (!Record[i])
				break;
			++i;
		} while (i < RecordSize);

		if (i == RecordSize)
			return 0xB;

		memmove(Record + 6, &Record[i], RecordSize - i);
		RecordSize += 6 - i;
		return 0;
	}
	default:
		return -1;
	}
}

uint32_t ComputeCRC(uint32_t dwCRC, uint8_t* pv, uint32_t cbLength);

void hsig_t::load(uint32_t sig_size, uint8_t*& buff, uint32_t& cur_off, uint32_t type)
{
	buff += 4;
	auto old_ptr = buff;
	hsig_t st{};
	st.infw = *(uint16_t*)buff;
	st.suspw = *(uint16_t*)(buff + 2);
	st.strcnt = *(uint16_t*)(buff + 4);
	st.type = type;

	auto endp = &buff[sig_size];
	auto  hstr_body = buff + 6;
	uint32_t  i1 = 0;
	auto  _ch = hstr_body;
	//跳过name

	while (_ch < endp) {
		if (*_ch) {
			++i1;
			++_ch;
			if (i1 < 0x40)
				continue;
		}

		auto p1 = &hstr_body[i1];
		//必须为0x00
		if (*p1)
			throw std::runtime_error("invaild sig");

		auto p2 = p1 + 1;
		uint32_t i = 0;

		while (i < st.strcnt) {
			sstring_t ss{};

			ss.w = *(uint16_t*)p2;
			ss.size = p2[2];

			uint32_t flags = 0;
			uint32_t skip_size;
			if (type == SIGNATURE_TYPE_PEHSTR) {
				flags = 0;
				skip_size = 3;
			}
			else {
				skip_size = 4;
				flags = *(p2 + 3);
				if (flags & 0x80) {
					flags |= *(p2 + 4) << 8;
					p2 += 1;
				}
				if (flags & 0x8000) {
					flags |= *(uint16_t*)(p2 + 4) << 0x10;
					p2 += 2;
				}
			}
			ss.flags = flags;
			ss.ofs = g_sstrs.size();
			g_sstrs.insert(g_sstrs.end(), (char*)(p2 + skip_size), (char*)(p2 + skip_size + ss.size));
			st.strs.push_back(ss);
			p2 += ss.size + skip_size;
			++i;
		}
		st.index = *p2;
		st.lowfiw = *(p2 + 1);

		st.threat_id = g_CurrentThreatID;
		st.sig_id = g_CurrentSigID;

		uint32_t recordSize = sig_size;
		std::vector<uint8_t> tmpbuf = std::vector<uint8_t>(sig_size);
		tmpbuf.insert(tmpbuf.begin(), old_ptr, old_ptr + sig_size);

		auto result = RemoveRecordName((signature_type)st.type, recordSize, (uint8_t*)&tmpbuf[0]);
		if (!result || result == 0x490) {
			st.sigseq = ComputeCRC(-1, &tmpbuf[0], recordSize) |
				((uint64_t)st.type << 0x20) |
				((uint64_t)recordSize << 0x28);
		}

		std::vector<uint8_t>().swap(tmpbuf);
		g_hstrSignatures.push_back(st);
		buff += sig_size;
		cur_off += sig_size + 4;
		return;
	}
}

const char* get_hstr_type(signature_type type) {
	switch (type)
	{
	case SIGNATURE_TYPE_PEHSTR_EXT:
		return "SIGNATURE_TYPE_PEHSTR_EXT";
	case SIGNATURE_TYPE_PEHSTR:
		return "SIGNATURE_TYPE_PEHSTR";
	case SIGNATURE_TYPE_ARHSTR_EXT:
		return "SIGNATURE_TYPE_ARHSTR_EXT";
	case SIGNATURE_TYPE_DEXHSTR_EXT:
		return "SIGNATURE_TYPE_DEXHSTR_EXT";
	case SIGNATURE_TYPE_MACROHSTR_EXT:
		return "SIGNATURE_TYPE_MACROHSTR_EXT";
	case SIGNATURE_TYPE_MACHOHSTR_EXT:
		return "SIGNATURE_TYPE_MACHOHSTR_EXT";
	case SIGNATURE_TYPE_DOSHSTR_EXT:
		return "SIGNATURE_TYPE_DOSHSTR_EXT";
	case SIGNATURE_TYPE_JAVAHSTR_EXT:
		return "SIGNATURE_TYPE_JAVAHSTR_EXT";
	case SIGNATURE_TYPE_ELFHSTR_EXT:
		return "SIGNATURE_TYPE_ELFHSTR_EXT";
	case SIGNATURE_TYPE_AUTOITHSTR_EXT:
		return "SIGNATURE_TYPE_AUTOITHSTR_EXT";
	case SIGNATURE_TYPE_INNOHSTR_EXT:
		return "SIGNATURE_TYPE_INNOHSTR_EXT";
	case SIGNATURE_TYPE_CMDHSTR_EXT:
		return "SIGNATURE_TYPE_CMDHSTR_EXT";
	case SIGNATURE_TYPE_SWFHSTR_EXT:
		return "SIGNATURE_TYPE_SWFHSTR_EXT";
	default:
		return "not hstr type";
	}
}

void hsig_t::format(std::vector<uint8_t>& vec)
{
	char buf[0x1000];

	sprintf(buf, "Name \"%s\"\nType %s\nInfW %d\nSuspW %d\nThreatID %0x\nSigID %0x\n\n",
		get_threat_name(this->threat_id).c_str(),
		get_hstr_type((signature_type)this->type),
		this->infw,
		this->suspw,
		this->threat_id,
		this->sig_id);
	vec.insert(vec.end(), (uint8_t*)buf, (uint8_t*)buf + strlen(buf));
	auto itor = g_pcode_sigs.find(this->sigseq);
	if (itor != g_pcode_sigs.end()) {
		sprintf(buf, "luaseq %I64x\n", this->sigseq);
		vec.insert(vec.end(), (uint8_t*)buf, (uint8_t*)buf + strlen(buf));
	}

	for (uint32_t i = 0; i < this->strcnt; ++i)
	{
		auto s = &this->strs[i];
		bool mod_s = true;
		bool mod_unicode = true;
		char buff2[0x1000] = {};
		if (s->flags == 0 || s->flags == 1) {
			auto p = &g_sstrs[s->ofs];
			for (uint32_t i = 0; i < s->size; ++i)
			{
				if (!isprint(p[i])) {
					mod_s = false;
					break;
				}
			}
			if (!mod_s && !(s->size % 2)) {
				for (uint32_t i = 0; i < s->size / 2; ++i)
				{
					if (!isprint(p[2 * i])) {
						mod_unicode = false;
						break;
					}
					if (p[2 * i + 1]) {
						mod_unicode = false;
						break;
					}
				}
				if (mod_unicode) {
					for (uint32_t i = 0; i < s->size / 2; ++i)
					{
						buff2[i] = p[2 * i];
					}
					sprintf_s(buf, 0x1000, "{%d,%d,u\"%s\"},\n", s->w, s->flags, buff2);
					vec.insert(vec.end(), (uint8_t*)buf, (uint8_t*)buf + strlen(buf));
					continue;
				}
			}

			if (mod_s) {
				memcpy(buff2, p, s->size);
				sprintf_s(buf, 0x1000, "{%d,%d,s\"%s\"},\n", s->w, s->flags, buff2);
				vec.insert(vec.end(), (uint8_t*)buf, (uint8_t*)buf + strlen(buf));
				continue;
			}
		}

		hex2str(&g_sstrs[s->ofs], s->size, buff2);
		sprintf(buf, "{%d,%d,b\"%s\"},\n", s->w, s->flags, buff2);
		vec.insert(vec.end(), (uint8_t*)buf, (uint8_t*)buf + strlen(buf));
	}

	const char* endstr = "END\n\n";
	vec.insert(vec.end(), (uint8_t*)endstr, (uint8_t*)endstr + strlen(endstr));
}

void staticrec_t::load(uint32_t sig_size, uint8_t*& buff, uint32_t& cur_off)
{
	buff += 4;
	staticrec_t st{};
	st.dwPartialCRC1 = *(uint32_t*)buff;
	st.dwPartialCRC2 = *(uint32_t*)(buff + 0x04);
	st.dwPartialCRC3 = *(uint32_t*)(buff + 0x08);
	st.dwSize = *(uint32_t*)(buff + 0x0c);
	uint32_t flag = *(uint16_t*)(buff + 0x10);
	st.dwNoSizeCheck = flag & 0x01;
	st.dwHashType = flag >> 0x0c;

	uint32_t hashSize = GetHashSizeFromType(st.dwHashType);
	if (hashSize == -1) {
		//未知类型
		st.dwHash = -1;
	}
	else if (hashSize == 4) {
		st.dwHash = *(uint32_t*)(buff + 0x12);
	}
	else {
		st.dwExtraOffset = g_hash_vals.size();
		g_hash_vals.insert(g_hash_vals.end(), buff + 0x12, buff + 0x12 + hashSize);
	}
	st.threatID = g_CurrentThreatID;
	st.sigId = g_CurrentSigID;

	g_db.static_rec.push_back(st);
	buff += sig_size;
	cur_off += sig_size + 4;
}

void kcrce_t::load(uint32_t sig_size, uint8_t*& buff, uint32_t& cur_off)
{
	buff += 4;
	kcrce_t st{};

	st.fastcrc = *(uint32_t*)buff;
	st.crc1 = *(uint32_t*)(buff + 0x04);
	st.crc2 = *(uint32_t*)(buff + 0x08);
	st.lenofs2 = *(uint32_t*)(buff + 0x0c);
	st.threatID = g_CurrentThreatID;
	st.sigId = g_CurrentSigID;

	g_db.pestatic_rec.push_back(st);
	buff += sig_size;
	cur_off += sig_size + 4;
}

void peemusig_t::load(uint32_t sig_size, uint8_t*& buff, uint32_t& cur_off)
{
	buff += 4;
	peemusig_t st{};

	st.mcrc = *(uint32_t*)buff;
	st.lcrc = *(uint32_t*)(buff + 4);
	st.lcrcofs = *(uint16_t*)(buff + 8);
	st.lcrclen = *(uint16_t*)(buff + 10);
	st.moffset = *(uint16_t*)(buff + 12);
	st.flags = *(uint16_t*)(buff + 14);
	g_db.peemu_rec.push_back(st);

	buff += sig_size;
	cur_off += sig_size + 4;
}

const char* get_nid_type_str(nid_t type) {
	switch (type)
	{
	case NID_SCAN_ALG:
		return "NID_SCAN_ALG";
	case NID_SCAN_END:
		return "NID_SCAN_END";
	case NID_SCAN_LSCN_E8BE:
		return "NID_SCAN_LSCN_E8BE";
	case NID_INI:
		return "NID_INI";
	case NID_IRC:
		return "NID_IRC";
	case NID_SWF:
		return "NID_SWF";
	case NID_FORMACTION:
		return "NID_FORMACTION";
	case NID_VBPCRC:
		return "NID_VBPCRC";
	case NID_VNAME:
		return "NID_VNAME";
	case NID_ALGO_PEFILE:
		return "NID_ALGO_PEFILE";
	case NID_ALGO_NEFILE:
		return "NID_ALGO_NEFILE";
	case NID_NEWCODEBASE:
		return 	"NID_NEWCODEBASE";
	case NID_NEWIFRAME:
		return "NID_NEWIFRAME";
	case NID_WORD2:
		return "NID_WORD2";
	case NID_LMDB:
		return "NID_LMDB";
	case NID_ELFALGO:
		return "NID_ELFALGO";
	case NID_JAVACRC:
		return "NID_JAVACRC";
	case NID_JETDBCRC:
		return "NID_JETDBCRC";
	case NID_VBA_PCRC1:
		return "NID_VBA_PCRC1";
	case NID_VBA_PCRC2:
		return "NID_VBA_PCRC2";
	case NID_VBA_SRCCRC:
		return "NID_VBA_SRCCRC";
	case NID_X5_SKELCRC:
		return "NID_X5_SKELCRC";
	case NID_INSTALLER_INNO:
		return "NID_INSTALLER_INNO";
	case NID_DELAYED_REPORTING:
		return "NID_DELAYED_REPORTING";
	case NID_LOWFI_SIG:
		return "NID_LOWFI_SIG";
	case NID_IL_PATTERN:
		return "NID_IL_PATTERN";
	case NID_PDBPCRC:
		return "NID_PDBPCRC";
	case NID_IMPHASH_SIG:
		return "NID_IMPHASH_SIG";
	case NID_CONTINUE_CONTAINER_SCAN_AFTER_DETECTION:
		return "NID_CONTINUE_CONTAINER_SCAN_AFTER_DETECTION";
	case NID_ZKM_HASH:
		return "NID_ZKM_HASH";
	case NID_SECTIONHDR_HASH:
		return "NID_SECTIONHDR_HASH";
	case NID_PEVARS_HASH:
		return "NID_PEVARS_HASH";
	case NID_MSILGUID_SIG:
		return "NID_MSILGUID_SIG";
	case NID_EXPORTS_HASH:
		return "NID_EXPORTS_HASH";
	case NID_DISABLE_DT_ON_KNOWN_STUB:
		return "NID_DISABLE_DT_ON_KNOWN_STUB";
	case NID_IMPHASH_ORDINAL_TO_NAME:
		return "NID_IMPHASH_ORDINAL_TO_NAME";
	case NID_UNRELIABLE_SHORT_CRC:
		return "NID_UNRELIABLE_SHORT_CRC";
	case NID_ACTIONS:
		return "NID_ACTIONS";
	case NID_FPCEHCK_EXCLUDED_CERTIFICATE:
		return "NID_FPCEHCK_EXCLUDED_CERTIFICATE";
	case NID_DT_CONTINUE_AFTER_UNPACKING:
		return "NID_DT_CONTINUE_AFTER_UNPACKING";
	case NID_SKIP_CRC16:
		return "NID_SKIP_CRC16";
	case NID_SKIP_FIRST4:
		return "NID_SKIP_FIRST4";
	case NID_FPCHECK_EXCLUDED_SIGNATURE:
		return "NID_FPCHECK_EXCLUDED_SIGNATURE";
	case NID_REPORT_AS_FRIENDLY:
		return "NID_REPORT_AS_FRIENDLY";
	case NID_W6PASSWORD:
		return "NID_W6PASSWORD";
	case NID_APISET_REDIRECT:
		return "NID_APISET_REDIRECT";
	case NID_DISABLE_API_LIMITS:
		return "NID_DISABLE_API_LIMITS";
	case NID_DISABLE_SEH_LIMIT:
		return "NID_DISABLE_SEH_LIMIT";
	case NID_INTERESTING_SWF_TAG:
		return "NID_INTERESTING_SWF_TAG";
	case NID_SKIP_CRC8:
		return "NID_SKIP_CRC8";
	case NID_ENABLE_VMM_GROW:
		return "NID_ENABLE_VMM_GROW";
	case NID_SYNCLOWFI_SIG:
		return "NID_SYNCLOWFI_SIG";
	case NID_ENABLE_HSTR_EXHAUSTIVE:
		return "NID_ENABLE_HSTR_EXHAUSTIVE";
	case NID_TELEMETRY_ONLY_SIG:
		return "NID_TELEMETRY_ONLY_SIG";
	case NID_ENABLE_AGGRESIVE_IMPORTS:
		return "NID_ENABLE_AGGRESIVE_IMPORTS";
	case NID_INTERESTING_EXPORT:
		return "NID_INTERESTING_EXPORT";
	case NID_SFX_WINRAR:
		return "NID_SFX_WINRAR";
	case NID_PERSIST:
		return "NID_PERSIST";
	case NID_SAMPLE_ONLY_SIG:
		return "NID_SAMPLE_ONLY_SIG";
	case NID_INSTALLER_NSIS2:
		return "NID_INSTALLER_NSIS2";
	case NID_UNRELIABLE_LONG_CRC:
		return "NID_UNRELIABLE_LONG_CRC";
	case NID_ENABLE_DEEP_ANALYSIS:
		return "NID_ENABLE_DEEP_ANALYSIS";
	case NID_REPORT_LOWFI:
		return "NID_REPORT_LOWFI";
	case NID_SPECIAL_MACRO_REMOVAL:
		return "NID_SPECIAL_MACRO_REMOVAL";
	case NID_NONCACHED_LOWFI:
		return "NID_NONCACHED_LOWFI";
	case NID_LOWFI_CACHE_PER_TRIGGER:
		return "NID_LOWFI_CACHE_PER_TRIGGER";
	case NID_PEFILENAME_HASH:
		return "NID_PEFILENAME_HASH";
	case NID_ANYFILENAME_HASH:
		return "NID_ANYFILENAME_HASH";
	case NID_EMU_HARDCODED_API_ADDR:
		return "NID_EMU_HARDCODED_API_ADDR";
	case NID_HAS_ATTRMATCH_HANDLER:
		return "NID_HAS_ATTRMATCH_HANDLER";
	case NID_AUTOLOWFI_EXCLUSION:
		return "NID_AUTOLOWFI_EXCLUSION";
	case NID_DT_CONTINUE_AFTER_DAMAGED_UNPACKING:
		return "NID_DT_CONTINUE_AFTER_DAMAGED_UNPACKING";
	case NID_BAD_MACHINE_GUID:
		return "NID_BAD_MACHINE_GUID";
	case NID_APPX_GOOD_PUB:
		return "NID_APPX_GOOD_PUB";
	case NID_DTEVENTS_HASH:
		return "NID_DTEVENTS_HASH";
	case NID_UNINTERESTING_FILE_HASH:
		return "NID_UNINTERESTING_FILE_HASH";
	case NID_APPX_BAD_ID:
		return "NID_APPX_BAD_ID";
	case NID_LOWFI_FORCE_SYNC:
		return "NID_LOWFI_FORCE_SYNC";
	case NID_INCLUDE_DNS_CACHE_INFO:
		return "NID_INCLUDE_DNS_CACHE_INFO";
	case NID_SYSCALLS_HASH:
		return "NID_SYSCALLS_HASH";
	default:
		return "unkonw nid type";
	}
};

void nid_entry_t::load(uint32_t sig_size, uint8_t*& buff, uint32_t& cur_off)
{
	buff += 4;
	nid_entry_t st{};
	st.id = *(uint32_t*)buff;
	st.type = (nid_t)buff[4];
	st.threat_id = g_CurrentThreatID;
	st.sig_id = g_CurrentSigID;
	if (st.type != 0xFF) {
		g_db.nid_rec.push_back(st);
	}

	buff += sig_size;
	cur_off += sig_size + 4;
}

void nid_entry_t::format(std::vector<uint8_t>& vec)
{
	char buf[0x100];
	sprintf(buf, "{%s,%s,0x%0x},\n", get_threat_name(this->threat_id).c_str(), get_nid_type_str(type), id);
	vec.insert(vec.end(), (uint8_t*)buf, (uint8_t*)buf + strlen(buf));
}

void nid64_entry_t::load(uint32_t sig_size, uint8_t*& buff, uint32_t& cur_off)
{
	buff += 4;
	nid64_entry_t st{};
	st.id = *(uint64_t*)buff;
	st.type = (nid_t)buff[8];
	st.threat_id = g_CurrentThreatID;
	st.sig_id = g_CurrentSigID;
	if (st.type != 0xFF) {
		g_db.nid64_rec.push_back(st);
	}

	buff += sig_size;
	cur_off += sig_size + 4;
}

void nid64_entry_t::format(std::vector<uint8_t>& vec)
{
	char buf[0x100];
	sprintf(buf, "{%s,%s,0x%0I64x},\n", get_threat_name(this->threat_id).c_str(), get_nid_type_str(type), id);
	vec.insert(vec.end(), (uint8_t*)buf, (uint8_t*)buf + strlen(buf));
}

void snid_entry_t::load(uint32_t sig_size, uint8_t*& buff, uint32_t& cur_off)
{
	buff += 4;
	snid_entry_t st{};
	memcpy(st.sha1, buff, 0x14);
	st.type = (nid_t)buff[0x14];
	st.threat_id = g_CurrentThreatID;
	st.sig_id = g_CurrentSigID;
	g_db.snid_rec.push_back(st);
	buff += sig_size;
	cur_off += sig_size + 4;
}

void snid_entry_t::format(std::vector<uint8_t>& vec)
{
	char buf[0x200] = {};
	char hex_str[41] = {};
	hex2str(sha1, 20, hex_str);

	sprintf(buf, "{%s,%s,\"%s\"},\n", get_threat_name(this->threat_id).c_str(), get_nid_type_str(type), hex_str);
	vec.insert(vec.end(), (uint8_t*)buf, (uint8_t*)buf + strlen(buf));
}

void pcode_virrec::load(uint32_t sig_size, uint8_t*& buff, uint32_t& cur_off, bool externd)
{
	buff += 4;
	pcode_virrec st{};
	st.crc = *(safecrc_t*)buff;
	st.crcgen = *(safecrc_t*)(buff + 0x08);
	st.crclike = *(safecrc_t*)(buff + 0x10);
	st.flags = externd;
	g_db.pcode_rec.push_back(st);
	buff += sig_size;
	cur_off += sig_size + 4;
}

uint64_t  strlenNoNull(const char* Buffer, uint64_t BufferSize)
{
	uint64_t i;
	for (i = 0; i < BufferSize; ++i)
	{
		if (!Buffer[i])
			break;
	}
	return i;
}

//mpengine.dll的函数ReceiveNewTemplate简化版
void ReceiveNewTemplate(
	uint32_t sig_size,
	uint8_t*& buff,
	uint32_t& cur_off,
	uint8_t* vector,
	uint64_t elementfields,
	const uint64_t* elementdesc) {
	buff += 4;
	uint32_t i = 0;

	auto p = buff;
	auto endp = &buff[sig_size];

	while (i < elementfields) {
		uint64_t buf_ofs = elementdesc[i + 1];
		auto date_type = elementdesc[i] & 0xFFFF;

		if (date_type - 0x2001 <= 0xFFD) {
			auto buf_size = date_type - 0x2000;
			memmove(vector + buf_ofs, p, buf_size);
			p += buf_size;
			i += 2;
			continue;
		}

		switch (date_type)
		{
		case 0x1000:
			*(uint32_t*)(vector + buf_ofs) = *(uint32_t*)p;
			p += 4;
			break;
		case 0x1001:
			*(uint16_t*)(vector + buf_ofs) = *(uint16_t*)p;
			p += 2;
			break;
		case 0x1002:
			*(uint8_t*)(vector + buf_ofs) = *(uint8_t*)p;
			p += 1;
			break;
		case 0x1005: //nameID
		{
			auto len = strlenNoNull((const char*)p, endp - p) + 1;
			*(uint32_t*)(vector + buf_ofs) = -1;//nameid,暂时不处理
			p += len;
			break;
		}
		case 0x1006:
			break;
		case 0x1010:
			*(uint64_t*)(vector + buf_ofs) = *(uint64_t*)p;
			p += 8;
			break;
		case 0x1011://threatID
			*(uint32_t*)(vector + buf_ofs) = g_CurrentThreatID;
			break;
		case 0x1012://SigID
			*(uint32_t*)(vector + buf_ofs) = g_CurrentSigID;
			break;
		case 0x1013://SigSeq
			*(uint64_t*)(vector + buf_ofs) = -1;
			break;

		case 0x1016:
			//recID
			*(uint32_t*)(vector + buf_ofs) = -1;
			break;
		case 0x1009:
		{
			auto data_size = *(uint16_t*)p;
			*(uint32_t*)(vector + buf_ofs) = -1;//p+2开始大小data_size的数据
			p += data_size + 2;
			break;
		}
		case 0x100C:
		{
			//指针类型
			auto data_size = *(uint8_t*)p;
			*(uint32_t*)(vector + buf_ofs) = 0;//p+1开始大小data_size的数据
			p += data_size + 1;
			break;
			break;
		}

		default:
		{
			break;
		}
		}
		i += 2;
	}

	buff += sig_size;
	cur_off += sig_size + 4;
}

//搜索方法在bootsigsearch
void bootrecord_t::load(uint32_t sig_size, uint8_t*& buff, uint32_t& cur_off)
{
	const uint64_t bootrecord_desc[4] =
	{ 0x1016, 0, 0x2020, 4 };

	bootrecord_t rec{};
	ReceiveNewTemplate(sig_size, buff, cur_off, (uint8_t*)&rec, 4, bootrecord_desc);
	g_bsigs.push_back(rec);
}

void simple_rec_ex::load(uint32_t sig_size, uint8_t*& buff, uint32_t& cur_off)
{
	const uint64_t simple_rec_ex_desc[16] = {
	0x1000, 0, 0x1000, 4, 0x1001, 8, 0x1001, 0x0A, 0x1000, 0x0C,
	0x1000, 0x10, 0x40001016, 0x14, 0x1006, 0x18
	};

	simple_rec_ex rec{};
	ReceiveNewTemplate(sig_size, buff, cur_off, (uint8_t*)&rec, 0x10, simple_rec_ex_desc);
	g_nsrs.push_back(rec);
}

void simple_rec::load(uint32_t sig_size, uint8_t*& buff, uint32_t& cur_off)
{
	const uint64_t simple_rec_desc[18] = {
			0x1001,0x0,0x1001,0x2,0x1000,0x4,0x1001,0x8,0x1001,0x0A,
			0x1000,0x0C,0x1000,0x10,0x40001016,0x14,0x1006,0x18
	};
	simple_rec rec{};
	ReceiveNewTemplate(sig_size, buff, cur_off, (uint8_t*)&rec, 0x12, simple_rec_desc);
	g_srs.push_back(rec);
}

void poly_vir::load(uint32_t sig_size, uint8_t*& buff, uint32_t& cur_off)
{
	const uint64_t polyvirdesc[18] = {
			0x2010,0x00,0x1001,0x10,0x1001,0x12,0x1000,0x14,
			0x1001,0x18,0x1001,0x1A,0x1000,0x1C,0x1009,0x24,
			0x1016,0x20
	};
	poly_vir rec{};
	ReceiveNewTemplate(sig_size, buff, cur_off, (uint8_t*)&rec, 0x12, polyvirdesc);
	g_polyVirSignatures.push_back(rec);
}

void PCodeValidatorSig_t::load(uint32_t sig_size, uint8_t*& buff, uint32_t& cur_off)
{
	buff += 4;
	auto sigseq = *(uint64_t*)buff;
	uint32_t validator_flag = *(uint32_t*)(buff + 8);
	uint32_t luacode_size = *(uint32_t*)(buff + 12);
	char name[0x50] = {};
	sprintf(name, "WDExtract\\lua_validator\\%I64x.lua", sigseq);
	write_file(buff + 16, luacode_size, name);
	g_pcode_sigs.insert({ sigseq,{validator_flag} });
	buff += sig_size;
	cur_off += sig_size + 4;
}

uint32_t dllId = 0;

void vdll_t::load(uint32_t sig_size, uint8_t*& buff, uint32_t& cur_off, signature_type type)
{
	const char* dir;
	switch (type)
	{
	case SIGNATURE_TYPE_VDLL_X86:
		dir = "vdll_x86";
		break;
	case SIGNATURE_TYPE_VDLL_X64:
		dir = "vdll_x64";
		break;
	case SIGNATURE_TYPE_VDLL_MSIL:
		dir = "vdll_msil";
		break;
	default:
		break;
	}
	char name[0x100];
	//暂时使用ID作为文件名,提取真实文件名需要解析PE格式
	sprintf(name, "WDExtract\\%s\\%d.dll", dir, ++dllId);

	buff += 4;
	uint32_t image_size = *(uint32_t*)buff;
	write_file(buff, sig_size, name);

	buff += sig_size;
	cur_off += sig_size + 4;
}

uint32_t luafile_Id = 0;

void LuaStandalone_t::load(uint32_t sig_size, uint8_t*& buff, uint32_t& cur_off)
{
	buff += 4;
	uint8_t Category = buff[1];

	char name[0x50] = {};
	uint32_t lua_name_size = buff[0];

	sprintf(name, "WDExtract\\LuaStandalone\\%d.lua", ++luafile_Id);
	if (!buff[0]) {
		write_file(buff + 8, *(uint32_t*)(buff + 4), name);
	}
	else {
		write_file(buff + 8 + buff[0], *(uint32_t*)(buff + 4), name);
	}

	buff += sig_size;
	cur_off += sig_size + 4;
}

#include <filesystem>

namespace fs = std::filesystem;

template<class T>
void write_sig_to_file(std::vector<T>& sigs) {
	if (sigs.size() == 0)
		return;

	std::vector<uint8_t> vec;
	for (auto& n : sigs)
	{
		n.format(vec);
	}
	fs::path dir_path = "WDExtract";
	fs::path file_path = dir_path / T::name();
	write_file(&vec[0], vec.size(), file_path.string().c_str());
	std::vector<uint8_t>().swap(vec);
}

void write_format_db() {
	write_sig_to_file(g_db.nid_rec);
	write_sig_to_file(g_db.snid_rec);
	write_sig_to_file(g_db.nid64_rec);
	write_sig_to_file(g_hstrSignatures);
}