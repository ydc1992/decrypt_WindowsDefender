// deceypt_database.cpp: 定义应用程序的入口点。
//

#include "deceypt_database.h"
#include "signature.h"
#include <cstdint>
#include <map>

#include "zlib/zlib.h"
#include "pestudio.h"

#include <filesystem>

namespace fs = std::filesystem;
using namespace std;

extern uint32_t g_CurrentThreatID;
extern int32_t g_CurrentSigID;
extern std::map<uint64_t, PCodeValidatorSig_t> g_pcode_sigs;

struct sig_cnt_info {
	uint32_t type : 8;
	uint32_t size : 24;
};

void write_file(uint8_t* buff, uint64_t size, const char* name) {
	FILE* hWrite = fopen(name, "wb");
	fwrite(buff, 1, size, hWrite);
	fclose(hWrite);
}

uint32_t GetHashSizeFromType(uint32_t hashType) {
	switch (hashType)
	{
	case 0x00:
		return 16;
	case 0x01:
		return 20;
	case 0x02:
	case 0x03:
		return 4;
	case 0x07:
		return -1;
	default:
		throw std::runtime_error("无效hash类型");
	}
}

void LoadModuleHeader(FILE* fp, rmod_header* hdr, uint64_t* VdmOffset) {
	int buff[0x10];
	fseek(fp, 0, 0);
	uint32_t i = 0;
	uint32_t ResourceOffset = 0;
	while (true) {
		fread(buff, 1, 0x40, fp);
		if ((*(uint16_t*)buff) != 0x5A4D)
			break;
		resquery_t rquery{};
		rquery.Id[2] = -1;
		rquery.Name[0] = L"RT_RCDATA";
		rquery.Id[1] = 1000;
		pe_resource_data_entry_t res{};
		ResourceOffset = FindResourceOffset(fp, 0, (uint8_t*)buff, &rquery, &res);
		if (ResourceOffset == -1)
			return;
		fseek(fp, ResourceOffset, 0);
		if (++i > 2)
			break;
	}
	hdr->r_magic = buff[0];
	hdr->r_time = buff[1];
	hdr->r_crc = buff[2];
	hdr->r_flags = buff[3];
	hdr->r_codelen = buff[5];
	hdr->r_extralen = buff[7];
	hdr->r_initmodule = buff[8];
	hdr->r_cleanupmodule = buff[9];
	hdr->r_relocno = buff[10];
	hdr->r_importno = buff[11];
	hdr->r_hostos = buff[12];

	hdr->r_codeoffset = ResourceOffset + buff[4];
	hdr->r_exportno = buff[13];
	hdr->r_truecodelen = buff[14];
	hdr->r_numberofrecords = buff[15];
	hdr->r_extraoffset = ResourceOffset + buff[6];
	if (VdmOffset)
		*VdmOffset = ResourceOffset;
	return;
}

uint64_t g_lookup_cnt = 0;

std::vector<t_full_threat_record> g_full_threats;
std::map<uint32_t, std::pair<bool, std::vector<uint32_t> >>  g_ThreatDependencies;

void threat_info_receiver(uint32_t sig_size, uint8_t*& buff, uint32_t& cur_off) {
	buff += 4;

	g_CurrentThreatID = *(uint32_t*)(buff);
	uint32_t lookup_cnt = *(uint16_t*)(buff + 4);
	g_lookup_cnt += lookup_cnt;
	g_CurrentSigID = -1;

	auto n1 = *(uint16_t*)(buff + 6);
	auto category = *(uint16_t*)(buff + 8);
	auto name_size = *(uint16_t*)(buff + 10);

	t_full_threat_record t;
	t.flags = 0;
	t.threat_id = g_CurrentThreatID;
	if (name_size) {
		char name[0x100] = {};
		UnpackVirusName((char*)(buff + 12), (char*)name);
		t.name = std::string(name);
	}
	t.category = category;
	t.flags |= 0x80;

	//buff += name_size + 14;
	//有点小问题,有部分字段不知道是啥该怎么解析
	//if (lookup_cnt) {
	//	t.flags &= ~0x80;
	//	auto itor = g_ThreatDependencies.try_emplace({ t.threat_id });
	//	itor.first->second.first = true;
	//	for (uint32_t i = 0; i < lookup_cnt; ++i)
	//	{
	//		itor.first->second.second.push_back(*(uint32_t*)&buff);
	//		buff += 4;
	//	}
	//}
	//buff += 2 * n1;
	//t.Severity = *(uint8_t*)buff;
	//t.Action = *(uint8_t*)(buff + 1);
	//buff += 2;
	//t.ShortDescriptionID = *(uint16_t*)buff;
	//t.AdviceDescription = *(uint16_t*)(buff + 2);
	//buff += 4;
	g_full_threats.push_back(t);
	buff += sig_size;
	cur_off += sig_size + 4;
}

static void DispatchRecords_only_hstr(std::vector<uint8_t>& vec_buf) {
	uint32_t max_size = vec_buf.size();
	uint8_t* buff = &vec_buf[0];

	uint32_t cur_off = 0;
	while (cur_off < max_size) {
		auto s = (common_header*)buff;
		if (g_CurrentThreatID != 0x80000000)
			++g_CurrentSigID;

		switch (s->type)
		{
		case SIGNATURE_TYPE_THREAT_BEGIN://threat_info_receiver
			threat_info_receiver(s->size, buff, cur_off);
			continue;

		case SIGNATURE_TYPE_PEHSTR_EXT:
		case SIGNATURE_TYPE_PEHSTR:
		case SIGNATURE_TYPE_ARHSTR_EXT:
		case SIGNATURE_TYPE_DEXHSTR_EXT:
		case SIGNATURE_TYPE_MACROHSTR_EXT:
		case SIGNATURE_TYPE_MACHOHSTR_EXT:
		case SIGNATURE_TYPE_DOSHSTR_EXT:
		case SIGNATURE_TYPE_JAVAHSTR_EXT:
		case SIGNATURE_TYPE_ELFHSTR_EXT:
		case SIGNATURE_TYPE_AUTOITHSTR_EXT:
		case SIGNATURE_TYPE_INNOHSTR_EXT:
		case SIGNATURE_TYPE_CMDHSTR_EXT:
		case SIGNATURE_TYPE_SWFHSTR_EXT:
		{
			hsig_t::load(s->size, buff, cur_off, s->type);
			continue;
		}

		default:
			break;
		}

		buff += s->size + 4;
		cur_off += s->size + 4;
	}
}

static void DispatchRecords(std::vector<uint8_t>& vec_buf, bool only_hstr) {
	if (only_hstr) {
		DispatchRecords_only_hstr(vec_buf);
		return;
	}

	uint32_t max_size = vec_buf.size();
	uint8_t* buff = &vec_buf[0];

	uint32_t cur_off = 0;
	while (cur_off < max_size) {
		auto s = (common_header*)buff;
		if (g_CurrentThreatID != 0x80000000)
			++g_CurrentSigID;

		switch (s->type)
		{
		case SIGNATURE_TYPE_THREAT_BEGIN://threat_info_receiver
			threat_info_receiver(s->size, buff, cur_off);
			continue;

		case SIGNATURE_TYPE_THREAT_END:
			break;
		case SIGNATURE_TYPE_STATIC:
		{
			staticrec_t::load(s->size, buff, cur_off);
			continue;
		}
		case SIGNATURE_TYPE_KCRCE:
		{
			kcrce_t::load(s->size, buff, cur_off);
			continue;
		}
		case SIGNATURE_TYPE_PESTATIC:
		{
			kcrce_t::load(s->size, buff, cur_off);
			continue;
		}

		case SIGNATURE_TYPE_KVIR32:
		{
			peemusig_t::load(s->size, buff, cur_off);
			continue;
		}
		case SIGNATURE_TYPE_NID:
		{
			nid_entry_t::load(s->size, buff, cur_off);
			continue;
		}
		case SIGNATURE_TYPE_NID64:
		{
			nid64_entry_t::load(s->size, buff, cur_off);
			continue;
		}
		case SIGNATURE_TYPE_SNID:
		{
			snid_entry_t::load(s->size, buff, cur_off);
			continue;
		}
		case SIGNATURE_TYPE_PEHSTR_EXT:
		case SIGNATURE_TYPE_PEHSTR:
		case SIGNATURE_TYPE_ARHSTR_EXT:
		case SIGNATURE_TYPE_DEXHSTR_EXT:
		case SIGNATURE_TYPE_MACROHSTR_EXT:
		case SIGNATURE_TYPE_MACHOHSTR_EXT:
		case SIGNATURE_TYPE_DOSHSTR_EXT:
		case SIGNATURE_TYPE_JAVAHSTR_EXT:
		case SIGNATURE_TYPE_ELFHSTR_EXT:
		case SIGNATURE_TYPE_AUTOITHSTR_EXT:
		case SIGNATURE_TYPE_INNOHSTR_EXT:
		case SIGNATURE_TYPE_CMDHSTR_EXT:
		case SIGNATURE_TYPE_SWFHSTR_EXT:
		{
			hsig_t::load(s->size, buff, cur_off, s->type);
			continue;
		}
		case SIGNATURE_TYPE_MACRO_PCODE://macro_pcode_push
		{
			pcode_virrec::load(s->size, buff, cur_off, false);
			continue;
		}
		case SIGNATURE_TYPE_MACRO_PCODE64:
		{
			pcode_virrec::load(s->size, buff, cur_off, true);
			continue;
		}

		case SIGNATURE_TYPE_BOOT:
		{
			bootrecord_t::load(s->size, buff, cur_off);
			continue;
		}

		case SIGNATURE_TYPE_CKSIMPLEREC: {
			simple_rec_ex::load(s->size, buff, cur_off);
			continue;
		}
		case SIGNATURE_TYPE_CKOLDREC:
		{
			simple_rec::load(s->size, buff, cur_off);
			continue;
		}

		case SIGNATURE_TYPE_POLYVIR32:
		{
			poly_vir::load(s->size, buff, cur_off);
			continue;
		}
		case SIGNATURE_TYPE_PCODEVALIDATOR:
		{
			PCodeValidatorSig_t::load(s->size, buff, cur_off);
			continue;
		}

		case SIGNATURE_TYPE_VDLL_X86:
		case SIGNATURE_TYPE_VDLL_MSIL:
		case SIGNATURE_TYPE_VDLL_X64:
		{
			vdll_t::load(s->size, buff, cur_off, (signature_type)s->type);
			continue;
		}
		case SIGNATURE_TYPE_LUASTANDALONE:
		{
			LuaStandalone_t::load(s->size, buff, cur_off);
			continue;
		}

		case SIGNATURE_TYPE_NSCRIPT_SP://pushSP
		{
			break;
		}
		case SIGNATURE_TYPE_NSCRIPT_BRUTE:
			break;
		case SIGNATURE_TYPE_NSCRIPT_NORMAL://push
			break;
		case SIGNATURE_TYPE_TUNNEL_X86:
			break;
		case SIGNATURE_TYPE_SIGTREE://sig_push
			break;
		case SIGNATURE_TYPE_ASEP_FILEPATH:
			break;

		case SIGNATURE_TYPE_AAGGREGATOR:
			break;
		case SIGNATURE_TYPE_SIGTREE_EXT://sig_push_ext
			break;

		case SIGNATURE_TYPE_KPAT://ReceiveNewTemplate
			break;
		case SIGNATURE_TYPE_NDAT://ReceiveNewTemplate
			break;
		case SIGNATURE_TYPE_FILEPATH://file_path_DB_receiver
			break;
		case SIGNATURE_TYPE_DEFAULTS://DefaultsSignatureReceiver
			break;

		case SIGNATURE_TYPE_REGKEY://reg_key_DB_receiver
			break;
		case SIGNATURE_TYPE_MACRO_SOURCE://macro_source_push
			break;
		case SIGNATURE_TYPE_FOLDERNAME://folder_name_DB_receiver
			break;
		case SIGNATURE_TYPE_PEBMPAT:
			break;
		case SIGNATURE_TYPE_FOPEX:
			break;
		case SIGNATURE_TYPE_KPATEX:
			break;
		case SIGNATURE_TYPE_PESTATICEX:
			break;
		case SIGNATURE_TYPE_KCRCEX:
			break;
		case SIGNATURE_TYPE_THREAD_X86:
			break;
		case SIGNATURE_TYPE_SIGTREE_BM:
			break;
		case SIGNATURE_TYPE_BM_INFO:
			break;
		case SIGNATURE_TYPE_VBFOP://FopScanner::AddNewPattern_VB
		case SIGNATURE_TYPE_MSILFOP://FopScanner::AddNewPattern_MSIL
		case SIGNATURE_TYPE_FOP64://FopScanner::AddNewPattern_X64
		case SIGNATURE_TYPE_FOP://FopScanner::AddNewPattern_X86
		case SIGNATURE_TYPE_FOPEX64:
		case SIGNATURE_TYPE_VBFOPEX:
			break;
		case SIGNATURE_TYPE_VERSIONCHECK:
			break;

		case SIGNATURE_TYPE_BRUTE:
			break;
		case SIGNATURE_TYPE_REVOKED_CERTIFICATE:
			break;

		case SIGNATURE_TYPE_CLEANSCRIPT://sysclean_push
			break;
		case SIGNATURE_TYPE_HOSTSENTRY:
			break;
		case SIGNATURE_TYPE_NSCRIPT_CURE:
			break;
		case SIGNATURE_TYPE_PEFILE_CURE:
			break;
		case SIGNATURE_TYPE_PATTMATCH:
			break;
		case SIGNATURE_TYPE_RPFROUTINE:
			break;
		case SIGNATURE_TYPE_GENSFX:
			break;
		case SIGNATURE_TYPE_UNPLIB:
			break;
		case SIGNATURE_TYPE_DBVAR:
			break;
		case SIGNATURE_TYPE_REMOVAL_POLICY:
			break;

		case SIGNATURE_TYPE_SAMPLE_REQUEST:
			break;

		case SIGNATURE_TYPE_VDLL_META:
			break;

		case SIGNATURE_TYPE_VFILE:
			//只保存着文件名和其他信息
			break;
		case SIGNATURE_TYPE_VREG:
			//root reg_pathsize reg_path namesize name bufsize buf
			break;

		case SIGNATURE_TYPE_PEMAIN_LOCATOR:
			break;
		case SIGNATURE_TYPE_TARGET_SCRIPT_PCODE:
			break;
		case SIGNATURE_TYPE_SAMPLE_REQUEST_BY_NAME:
			break;
		case SIGNATURE_TYPE_REMOVAL_POLICY_BY_NAME:
			break;
		case SIGNATURE_TYPE_IL2_PATTERN:
			break;
		case SIGNATURE_TYPE_COMMON_CODE:
			break;

		case SIGNATURE_TYPE_VFILEEX:
			break;

		case SIGNATURE_TYPE_MAGICCODE:
			break;
		case SIGNATURE_TYPE_CLEANSTORE_RULE:
			break;
		case SIGNATURE_TYPE_THREAT_UPDATE_STATUS:
			break;

		case SIGNATURE_TYPE_JSINIT:
			break;
		case SIGNATURE_TYPE_FTRIE_POS:
			break;
		case SIGNATURE_TYPE_REWSIGS:
			break;
		case SIGNATURE_TYPE_LATENT_THREAT:
			break;
		case SIGNATURE_TYPE_TRUSTED_PUBLISHER:
			break;
		case SIGNATURE_TYPE_FRIENDLYFILE_SHA256:
			break;
		case SIGNATURE_TYPE_EXPLICITRESOURCE:
			break;
		case SIGNATURE_TYPE_AAGGREGATOREX:
			break;
		case SIGNATURE_TYPE_DMGHSTR_EXT:
			break;
		case SIGNATURE_TYPE_SNIDEX2:
			break;
		case SIGNATURE_TYPE_PUA_APPMAP:
			break;
		case SIGNATURE_TYPE_BLOOM_FILTER:
			break;
		case SIGNATURE_TYPE_TITANFLT:
			break;
		case SIGNATURE_TYPE_VDLL_META_X64:
			break;
		case SIGNATURE_TYPE_SNIDEX:
			break;
		case SIGNATURE_TYPE_BM_ENV_VAR_MAP:
			break;
		default:
			printf("unkown handler sig type\n");
			break;
		}

		buff += s->size + 4;
		cur_off += s->size + 4;
	}
}

uint32_t derypt_database(const char* path, std::vector<uint8_t>& origin_data) {
	FILE* fp = fopen(path, "rb");
	rmod_header hdr = {};
	uint64_t vmdOffset;
	LoadModuleHeader(fp, &hdr, &vmdOffset);
	fseek(fp, hdr.r_extraoffset, 0);

	uint32_t buf[2];
	fread(&buf, 1, 8, fp);
	origin_data = std::vector<uint8_t>(hdr.r_extralen);
	if (hdr.r_flags & 2) {
		auto filebuf = std::vector<uint8_t>(buf[0]);
		//+0x00  size
		//+0x08  crc32 checksum
		fread(&filebuf[0], 1, buf[0], fp);

		z_stream_s stream = {};

		stream.next_in = (uint8_t*)&filebuf[0];
		stream.avail_in = buf[0];
		stream.next_out = &origin_data[0];
		stream.avail_out = hdr.r_extralen;

		auto result = inflateInit2_(&stream, -MAX_WBITS, "1.2.3", sizeof(z_stream));
		if (result)
			return result;

		inflate(&stream, 0);
		std::vector<uint8_t>().swap(filebuf);
	}
	return 0;
}

int main()
{
	fs::path dir_path = "WDExtract";
	if (!fs::exists(dir_path)) {
		fs::create_directory(dir_path);
	}

	const char* dirs[] = {
	"lua_validator","vdll_x86","vdll_x64","vdll_msil",
	"LuaStandalone"
	};

	for (auto& d : dirs) {
		auto subdir = dir_path / d;
		if (!fs::exists(subdir)) {
			fs::create_directory(subdir);
		}
	}
	size_t outsize;
	std::vector<uint8_t> db_delta, db_base;
																						 
	derypt_database("mpasdlta.vdm", db_delta);
	derypt_database("mpasbase.vdm", db_base);
	std::vector<uint8_t> vec(db_delta.size() + db_base.size());
	delta_patch(vec, &outsize, &db_delta[0], &db_base[0]);
	vec.resize(outsize);
	DispatchRecords(vec, true);

	derypt_database("mpavdlta.vdm", db_delta);
	derypt_database("mpavbase.vdm", db_base);
	vec = std::vector<uint8_t>(db_delta.size() + db_base.size());
	delta_patch(vec, &outsize, &db_delta[0], &db_base[0]);
	vec.resize(outsize);
	DispatchRecords(vec, true);
	write_format_db();
	return 0;
}