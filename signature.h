#pragma once
#include <cstdint>
#include <vector>
#include <stdexcept>

void find_threat(uint32_t threat_index);

struct rmod_header {
	uint32_t r_magic;
	uint32_t r_time;
	uint32_t r_crc;
	uint32_t r_flags;
	uint32_t r_codeoffset;
	uint32_t r_codelen;
	uint32_t r_extraoffset;
	uint32_t r_extralen;
	uint32_t r_initmodule;
	uint32_t r_cleanupmodule;
	union {
		uint32_t r_relocno;
		uint32_t r_dbversion;
	};
	uint32_t r_importno;
	uint32_t r_hostos;
	uint32_t r_exportno;
	uint32_t r_truecodelen;
	uint32_t r_numberofrecords;
};

struct common_header {
	uint32_t type : 8;
	uint32_t size : 24;
};

enum signature_type {
	SIGNATURE_TYPE_RESERVED = 0x0001,
	SIGNATURE_TYPE_VOLATILE_THREAT_INFO = 0x0002,
	SIGNATURE_TYPE_POLYVIR32 = 0x0021,
	SIGNATURE_TYPE_KVIR32 = 0x0020,
	SIGNATURE_TYPE_PEFILE_CURE = 0x003d,
	SIGNATURE_TYPE_PEHSTR = 0x0061,
	SIGNATURE_TYPE_PEHSTR_EXT = 0x0078,
	SIGNATURE_TYPE_PEHSTR_EXT2 = 0x0085,
	SIGNATURE_TYPE_ELFHSTR_EXT = 0x008c,
	SIGNATURE_TYPE_MACHOHSTR_EXT = 0x008d,
	SIGNATURE_TYPE_DOSHSTR_EXT = 0x008e,
	SIGNATURE_TYPE_MACROHSTR_EXT = 0x008f,
	SIGNATURE_TYPE_DEXHSTR_EXT = 0x00be,
	SIGNATURE_TYPE_JAVAHSTR_EXT = 0x00bf,
	SIGNATURE_TYPE_ARHSTR_EXT = 0x00c5,
	SIGNATURE_TYPE_SWFHSTR_EXT = 0x00d1,
	SIGNATURE_TYPE_AUTOITHSTR_EXT = 0x00d3,
	SIGNATURE_TYPE_INNOHSTR_EXT = 0x00d4,
	SIGNATURE_TYPE_PEPCODE = 0x008a,
	SIGNATURE_TYPE_BOOT = 0x0044,
	SIGNATURE_TYPE_MAC_CURE = 0x003e,
	SIGNATURE_TYPE_MACRO_PCODE = 0x0042,
	SIGNATURE_TYPE_MACRO_PCODE64 = 0x00cf,
	SIGNATURE_TYPE_MACRO_SOURCE = 0x0043,
	SIGNATURE_TYPE_KCRCE = 0x0080,
	SIGNATURE_TYPE_NID = 0x0055,
	SIGNATURE_TYPE_NID64 = 0x00ce,
	SIGNATURE_TYPE_CKSIMPLEREC = 0x0050,
	SIGNATURE_TYPE_CKOLDREC = 0x0011,
	SIGNATURE_TYPE_KPAT = 0x00bb,
	SIGNATURE_TYPE_NSCRIPT_NORMAL = 0x0027,
	SIGNATURE_TYPE_NSCRIPT_SP = 0x0028,
	SIGNATURE_TYPE_NSCRIPT_BRUTE = 0x0029,
	SIGNATURE_TYPE_NSCRIPT_CURE = 0x002c,
	SIGNATURE_TYPE_RPFROUTINE = 0x0053,
	SIGNATURE_TYPE_SIGTREE = 0x0040,
	SIGNATURE_TYPE_SIGTREE_EXT = 0x0041,
	SIGNATURE_TYPE_CLEANSCRIPT = 0x0049,
	SIGNATURE_TYPE_DEFAULTS = 0x0058,
	SIGNATURE_TYPE_TITANFLT = 0x0030,
	SIGNATURE_TYPE_TARGET_SCRIPT = 0x004a,
	SIGNATURE_TYPE_TARGET_SCRIPT_PCODE = 0x0090,
	SIGNATURE_TYPE_TUNNEL = 0x0099,
	SIGNATURE_TYPE_TUNNEL_X86 = 0x0099,
	SIGNATURE_TYPE_TUNNEL_X64 = 0x009a,
	SIGNATURE_TYPE_TUNNEL_IA64 = 0x009b,
	SIGNATURE_TYPE_TUNNEL_ARM64 = 0x009b,
	SIGNATURE_TYPE_TUNNEL_ARM = 0x00b6,
	SIGNATURE_TYPE_GENSFX = 0x0056,
	SIGNATURE_TYPE_UNPLIB = 0x0057,
	SIGNATURE_TYPE_PATTMATCH = 0x0051,
	SIGNATURE_TYPE_PATTMATCH_DEVELOPER = 0x0052,
	SIGNATURE_TYPE_PATTMATCH_V2 = 0x0077,
	SIGNATURE_TYPE_PATTMATCH_V2_DEVELOPER = 0x0076,
	SIGNATURE_TYPE_DBVAR = 0x005b,
	SIGNATURE_TYPE_THREAT_BEGIN = 0x005c,
	SIGNATURE_TYPE_THREAT_END = 0x005d,
	SIGNATURE_TYPE_FILENAME = 0x005e,
	SIGNATURE_TYPE_FILEPATH = 0x005f,
	SIGNATURE_TYPE_FOLDERNAME = 0x0060,
	SIGNATURE_TYPE_LOCALHASH = 0x0062,
	SIGNATURE_TYPE_REGKEY = 0x0063,
	SIGNATURE_TYPE_HOSTSENTRY = 0x0064,
	SIGNATURE_TYPE_STATIC = 0x0067,
	SIGNATURE_TYPE_LATENT_THREAT = 0x0069,
	SIGNATURE_TYPE_REMOVAL_POLICY = 0x006a,
	SIGNATURE_TYPE_WVT_EXCEPTION = 0x006b,
	SIGNATURE_TYPE_REVOKED_CERTIFICATE = 0x006c,
	SIGNATURE_TYPE_TRUSTED_PUBLISHER = 0x0070,
	SIGNATURE_TYPE_ASEP_FILEPATH = 0x0071,
	SIGNATURE_TYPE_DELTA_BLOB = 0x0073,
	SIGNATURE_TYPE_DELTA_BLOB_RECINFO = 0x0074,
	SIGNATURE_TYPE_ASEP_FOLDERNAME = 0x0075,
	SIGNATURE_TYPE_VDLL = 0x0079,
	SIGNATURE_TYPE_VERSIONCHECK = 0x007a,
	SIGNATURE_TYPE_SAMPLE_REQUEST = 0x007b,
	SIGNATURE_TYPE_VDLL_X86 = 0x0079,
	SIGNATURE_TYPE_VDLL_X64 = 0x007c,
	SIGNATURE_TYPE_VDLL_IA64 = 0x0091,
	SIGNATURE_TYPE_VDLL_ARM = 0x009c,
	SIGNATURE_TYPE_VDLL_MSIL = 0x00c4,
	SIGNATURE_TYPE_SNID = 0x007e,
	SIGNATURE_TYPE_FOP = 0x007f,
	SIGNATURE_TYPE_FOPEX = 0x0089,
	SIGNATURE_TYPE_VFILE = 0x0083,
	SIGNATURE_TYPE_SIGFLAGS = 0x0084,
	SIGNATURE_TYPE_PEMAIN_LOCATOR = 0x0086,
	SIGNATURE_TYPE_PESTATIC = 0x0087,
	SIGNATURE_TYPE_UFSP_DISABLE = 0x0088,
	SIGNATURE_TYPE_IL_PATTERN = 0x008b,
	SIGNATURE_TYPE_IL2_PATTERN = 0x00a6,
	SIGNATURE_TYPE_PEBMPAT = 0x0095,
	SIGNATURE_TYPE_AAGGREGATOR = 0x0096,
	SIGNATURE_TYPE_SAMPLE_REQUEST_BY_NAME = 0x0097,
	SIGNATURE_TYPE_KPATEX = 0x00bc,
	SIGNATURE_TYPE_REMOVAL_POLICY_BY_NAME = 0x0098,
	SIGNATURE_TYPE_THREAD_X86 = 0x009d,
	SIGNATURE_TYPE_THREAD_X64 = 0x009e,
	SIGNATURE_TYPE_THREAD_IA64 = 0x009f,
	SIGNATURE_TYPE_THREAD_ARM64 = 0x009f,
	SIGNATURE_TYPE_THREAD_ARM = 0x00b7,
	SIGNATURE_TYPE_FRIENDLYFILE_SHA256 = 0x00a0,
	SIGNATURE_TYPE_FRIENDLYFILE_SHA512 = 0x00a1,
	SIGNATURE_TYPE_SHARED_THREAT = 0x00a2,
	SIGNATURE_TYPE_VDM_METADATA = 0x00a3,
	SIGNATURE_TYPE_VSTORE = 0x00a4,
	SIGNATURE_TYPE_VDLL_SYMINFO = 0x00a5,
	SIGNATURE_TYPE_BM_STATIC = 0x00a7,
	SIGNATURE_TYPE_BM_INFO = 0x00a8,
	SIGNATURE_TYPE_NDAT = 0x00a9,
	SIGNATURE_TYPE_FASTPATH_DATA = 0x00aa,
	SIGNATURE_TYPE_FASTPATH_SDN = 0x00ab,
	SIGNATURE_TYPE_FASTPATH_TDN = 0x00d8,
	SIGNATURE_TYPE_DATABASE_CERT = 0x00ac,
	SIGNATURE_TYPE_SOURCE_INFO = 0x00ad,
	SIGNATURE_TYPE_HIDDEN_FILE = 0x00ae,
	SIGNATURE_TYPE_COMMON_CODE = 0x00af,
	SIGNATURE_TYPE_VREG = 0x00b0,
	SIGNATURE_TYPE_NISBLOB = 0x00b1,
	SIGNATURE_TYPE_VFILEEX = 0x00b2,
	SIGNATURE_TYPE_SIGTREE_BM = 0x00b3,
	SIGNATURE_TYPE_VBFOP = 0x00b4,
	SIGNATURE_TYPE_VDLL_META = 0x00b5,
	SIGNATURE_TYPE_PCODEVALIDATOR = 0x00b8,
	SIGNATURE_TYPE_MSILFOP = 0x00ba,
	SIGNATURE_TYPE_LUASTANDALONE = 0x00bd,
	SIGNATURE_TYPE_MAGICCODE = 0x00c0,
	SIGNATURE_TYPE_CLEANSTORE_RULE = 0x00c1,
	SIGNATURE_TYPE_VDLL_CHECKSUM = 0x00c2,
	SIGNATURE_TYPE_THREAT_UPDATE_STATUS = 0x00c3,
	SIGNATURE_TYPE_MSILFOPEX = 0x00c6,
	SIGNATURE_TYPE_VBFOPEX = 0x00c7,
	SIGNATURE_TYPE_FOP64 = 0x00c8,
	SIGNATURE_TYPE_FOPEX64 = 0x00c9,
	SIGNATURE_TYPE_JSINIT = 0x00ca,
	SIGNATURE_TYPE_PESTATICEX = 0x00cb,
	SIGNATURE_TYPE_KCRCEX = 0x00cc,
	SIGNATURE_TYPE_FTRIE_POS = 0x00cd,
	SIGNATURE_TYPE_BRUTE = 0x00d0,
	SIGNATURE_TYPE_REWSIGS = 0x00d2,
	SIGNATURE_TYPE_ROOTCERTSTORE = 0x00d5,
	SIGNATURE_TYPE_EXPLICITRESOURCE = 0x00d6,
	SIGNATURE_TYPE_CMDHSTR_EXT = 0x00d7,
	SIGNATURE_TYPE_EXPLICITRESOURCEHASH = 0x00d9,
	SIGNATURE_TYPE_FASTPATH_SDN_EX = 0x00da,
	//新版本才有的类型
	SIGNATURE_TYPE_BLOOM_FILTER = 0x00db,
	SIGNATURE_TYPE_VDLL_META_X64 = 0x00e1,
	SIGNATURE_TYPE_SNIDEX = 0x00e5,
	SIGNATURE_TYPE_SNIDEX2 = 0x00e6,
	SIGNATURE_TYPE_AAGGREGATOREX = 0x00e7,
	SIGNATURE_TYPE_PUA_APPMAP = 0x00e8,
	SIGNATURE_TYPE_DMGHSTR_EXT = 0x00ea,
	SIGNATURE_TYPE_BM_ENV_VAR_MAP = 0x00ed,
};

enum nid_t :uint8_t {
	NID_SCAN_ALG = 0x0001,
	NID_SCAN_END = 0x0002,
	NID_SCAN_LSCN_E8BE = 0x0003,
	NID_INI = 0x0004,
	NID_IRC = 0x0005,
	NID_SWF = 0x0006,
	NID_FORMACTION = 0x0007,
	NID_LAMEKCRC = 0x0008,
	NID_PEALG = 0x0009,
	NID_IFRAME = 0x000a,
	NID_VBPCRC = 0x000b,
	NID_CODEBASE = 0x000c,
	NID_UNRELIABLE_SHORT_CRC = 0x000d,
	NID_UNRELIABLE_LONG_CRC = 0x000e,
	NID_SKIP_CRC16 = 0x000f,
	NID_SKIP_FIRST4 = 0x0010,
	NID_VNAME = 0x0011,
	NID_ALGO_PEFILE = 0x0012,
	NID_ALGO_NEFILE = 0x0013,
	NID_SKIP_CRC8 = 0x0014,
	NID_NEWCODEBASE = 0x0015,
	NID_NEWIFRAME = 0x0016,
	NID_API_POLYENG = 0x0017,
	NID_WORD2 = 0x0018,
	NID_LMDB = 0x0019,
	NID_ELFALGO = 0x001a,
	NID_JAVACRC = 0x001b,
	NID_ACTIONS = 0x001c,
	NID_JETDBCRC = 0x001d,
	NID_VBA_PCRC1 = 0x001e,
	NID_VBA_PCRC2 = 0x001f,
	NID_VBA_SRCCRC = 0x0020,
	NID_X5_SKELCRC = 0x0021,
	NID_EMU_LOOPA_DISABLE = 0x0022,
	NID_EMU_LOOPA_ENABLE = 0x0023,
	NID_EMU_HARDCODED_API_ADDR = 0x0024,
	NID_SYSCALLS_HASH = 0x0025,
	NID_SYSCALLS_HASH_SPECIAL = 0x0026,
	NID_INTERESTING_EXPORT = 0x0027,
	NID_SFX_WINRAR = 0x0028,
	NID_INSTALLER_NSIS2 = 0x0029,
	NID_INSTALLER_INNO = 0x002a,
	NID_ENABLE_VMM_GROW = 0x002b,
	NID_ENABLE_AGGRESIVE_IMPORTS = 0x002c,
	NID_ENABLE_DEEP_ANALYSIS = 0x002d,
	NID_ENABLE_HSTR_EXHAUSTIVE = 0x002e,
	NID_W6PASSWORD = 0x002f,
	NID_DT_CONTINUE_AFTER_UNPACKING = 0x0030,
	NID_DT_SKIP_UNIMPLEMENTED_OPCODES = 0x0031,
	NID_DT_DISABLE_SKIP_UNIMPLEMENTED_OPCODES = 0x0032,
	NID_SAMPLE_ONLY_SIG = 0x0033,
	NID_DELAYED_REPORTING = 0x0034,
	NID_DISABLE_API_LIMITS = 0x0035,
	NID_DISABLE_SEH_LIMIT = 0x0036,
	NID_CERT_THUMBPRINT = 0x0037,
	NID_DT_CONTINUE_AFTER_DAMAGED_UNPACKING = 0x0038,
	NID_DISABLE_DT_ON_KNOWN_STUB = 0x0039,
	NID_LOWFI_SIG = 0x003a,
	NID_LOWFI_TYPE_1 = 0x003b,
	NID_LOWFI_TYPE_2 = 0x003c,
	NID_LOWFI_TYPE_3 = 0x003d,
	NID_REPORT_AS_FRIENDLY = 0x003e,
	NID_IL_PATTERN = 0x003f,
	NID_INTERESTING_SWF_TAG = 0x0040,
	NID_DT_DISABLE_STATIC_UNPACKING = 0x0042,
	NID_DT_ENABLE_STATIC_UNPACKING = 0x0043,
	NID_UNINTERESTING_FILE_HASH = 0x0044,
	NID_DT_DISABLE_MICROCODE = 0x0045,
	NID_DT_ENABLE_MICROCODE = 0x0046,
	NID_SPECIAL_MACRO_REMOVAL = 0x0047,
	NID_DISABLE_THREAD_API_LIMITS = 0x0048,
	NID_DEEP_API_LIMITS = 0x0049,
	NID_ENABLE_REEMULATION = 0x004a,
	NID_ENABLE_VM_RESCAN = 0x004b,
	NID_INET_DOMAIN = 0x004c,
	NID_PDBPCRC = 0x004d,
	NID_SYNCLOWFI_SIG = 0x004e,
	NID_FPCEHCK_EXCLUDED_CERTIFICATE = 0x004f,
	NID_FPCHECK_EXCLUDED_SIGNATURE = 0x0050,
	NID_AUTOLOWFI_EXCLUSION = 0x0051,
	NID_APPX_BAD_ID = 0x0052,
	NID_APPX_GOOD_ID = 0x0053,
	NID_APPX_BAD_PUB = 0x0054,
	NID_APPX_GOOD_PUB = 0x0055,
	NID_BAD_MACHINE_GUID = 0x0056,
	NID_FILTER_TRUSTED_LOWFI = 0x0057,
	NID_FILTER_TRUSTED_SAMPLEREQ = 0x0058,
	NID_PERSIST = 0x0059,
	NID_FILTER_TRUSTED_PERSIST = 0x005a,
	NID_FILTER_SIGNED = 0x005b,
	NID_NONCACHED_LOWFI = 0x005c,
	NID_REPORT_LOWFI = 0x005d,
	NID_EXTENDED_REPORT = 0x005e,
	NID_TELEMETRY_ONLY_SIG = 0x005f,
	NID_LOWFI_PER_FILE = 0x0060,
	NID_IMPHASH_ORDINAL_TO_NAME = 0x0061,
	NID_IMPHASH_SIG = 0x0062,
	NID_APISET_REDIRECT = 0x0063,
	NID_LOWFI_FORCE_SYNC = 0x0064,
	NID_LOWFI_FORCE_TELEMETRYONLY = 0x0065,
	NID_LOWFI_FORCE_ASYNC = 0x0066,
	NID_INCLUDE_DNS_CACHE_INFO = 0x0067,
	NID_HAS_ATTRMATCH_HANDLER = 0x0068,
	NID_CONTINUE_CONTAINER_SCAN_AFTER_DETECTION = 0x0069,
	NID_LOWFI_CACHE_PER_TRIGGER = 0x006a,
	NID_OLD_MACRO_REMOVAL = 0x006b,
	NID_REPORT_AS_SUSPICIOUS = 0x006c,
	NID_FILTER_NO_MOTW = 0x006d,
	NID_FILEQUERY_ONLY = 0x006e,
	NID_REQUEST_HOOKWOW = 0x006f,
	NID_SCRIPTSRC = 0x0070,
	NID_ENABLE_FDR = 0x0071,
	NID_VERSIONED_TRIGGER = 0x0072,
	NID_PDFURI = 0x0073,
	NID_ENABLE_LFR = 0x0074,
	NID_ENABLE_EXTENDED_BAFS = 0x0075,
	NID_FORCE_SYNC_QUERIES = 0x0076,
	NID_ALLOW_DYNAPI = 0x0077,
	NID_ORGID_DISABLE_FP_SUPRESSION = 0x0078,
	NID_ESU_VERSION = 0x0079,
	NID_BF_VERSION = 0x007a,
	NID_ZKM_HASH = 0x00c8,
	NID_PEFILENAME_HASH = 0x00c9,
	NID_ANYFILENAME_HASH = 0x00ca,
	NID_SECTIONHDR_HASH = 0x00cb,
	NID_PEVARS_HASH = 0x00cc,
	NID_MSILGUID_SIG = 0x00cd,
	NID_EXPORTS_HASH = 0x00ce,
	NID_DTEVENTS_HASH = 0x00cf,
	NID_DELPHIPACKAGE_HASH = 0x00d0,
	NID_MPATTRIBUTE_MAP = 0x00d1,
	NID_FOLDERNAME_HASH = 0x00d2,
	NID_PESTRUCT_HASH = 0x00d3,
	NID_ENABLE_EVAL = 0x00d4,
	NID_INSTALLER_OTHER = 0x00d5,
	NID_RESERVED = 0x00ff,
};

uint32_t GetHashSizeFromType(uint32_t hashType);

struct sstring_t {
	int16_t w;
	uint8_t size;
	uint16_t flags;
	uint32_t ofs;
};

/*
+0x00 w
+0x02 size
+0x03 flag  为1时区分大小写  为2时有通配符 为0x100为unicode
*/

struct hsig_t {
public:
	static void load(uint32_t sig_size, uint8_t*& buff, uint32_t& cur_off, uint32_t type);
	void format(std::vector<uint8_t>&);
	static const char* name() {
		return "hstr.sig";
	}
public:
	std::vector<sstring_t> strs;
	uint16_t infw;
	uint16_t suspw;
	uint16_t lowfiw;
	uint16_t strcnt;
	uint16_t index;
	uint16_t flags;
	uint32_t type;

	uint32_t threat_id;
	uint32_t sig_id;
	uint64_t sigseq;
};

struct staticrec_t {
public:
	static void load(uint32_t sig_size, uint8_t*& buff, uint32_t& cur_off);
public:
	uint32_t dwPartialCRC1;//文件头0x1000大小
	uint32_t dwPartialCRC2;//尾部crc
	uint32_t dwPartialCRC3;//文件头部0x10000的大小
	uint32_t dwSize : 28;
	uint32_t dwNoSizeCheck : 1;
	/*
	0x01 sha1
	0x02 crc32
	0x03 md5
	*/
	uint32_t dwHashType : 3;
	union {
		uint32_t dwHash;
		uint32_t dwExtraOffset;
	};
	uint32_t threatID;
	uint32_t sigId;
};

//kSearchUsingCRCs
struct kcrce_t {
	static void load(uint32_t sig_size, uint8_t*& buff, uint32_t& cur_off);
public:
	uint32_t fastcrc;
	uint32_t crc1;
	uint32_t crc2;
	uint32_t lenofs2;
	uint32_t threatID;
	uint32_t sigId;
};

//kvscanpage4sig
struct peemusig_t {
public:
	static void load(uint32_t sig_size, uint8_t*& buff, uint32_t& cur_off);
public:
	uint32_t mcrc;
	uint32_t lcrc;
	uint16_t lcrcofs;
	uint16_t lcrclen;
	uint16_t moffset;
	uint16_t flags;
};

//nidsearchrecid
//nidsearchrecidex
struct nid_entry_t {
public:
	static void load(uint32_t sig_size, uint8_t*& buff, uint32_t& cur_off);
	void format(std::vector<uint8_t>&);

	static const char* name() {
		return "nid.sig";
	}
public:
	uint32_t id;
	nid_t type;
	uint32_t threat_id;
	uint32_t sig_id;
};

struct nid64_entry_t {
public:
	static void load(uint32_t sig_size, uint8_t*& buff, uint32_t& cur_off);
	void format(std::vector<uint8_t>&);

	static const char* name() {
		return "nid64.sig";
	}
public:
	uint64_t id;
	nid_t type;
	uint32_t threat_id;
	uint32_t sig_id;
};

//snidsearchrecidex
struct snid_entry_t {
public:
	static void load(uint32_t sig_size, uint8_t*& buff, uint32_t& cur_off);
	void format(std::vector<uint8_t>&);
	static const char* name() {
		return "snid.sig";
	}
public:
	uint8_t sha1[20];
	nid_t type;
	uint32_t threat_id;
	uint32_t sig_id;
};

struct safecrc_t {
	union {
		struct {
			uint32_t crc32;
			union {
				struct {
					uint16_t size;
					uint16_t crc16;
				};
				uint32_t crchigh;
			};
		};
		uint64_t crc64;
	};
};

struct pcode_virrec {
public:
	static void load(uint32_t sig_size, uint8_t*& buff, uint32_t& cur_off, bool externd);
public:
	safecrc_t crc;
	safecrc_t crcgen;
	safecrc_t crclike;
	uint32_t flags;
};

struct bootrecord_t {
public:
	static void load(uint32_t sig_size, uint8_t*& buff, uint32_t& cur_off);
public:
	uint32_t br_recid;
	uint8_t br_sig[32];
};

//knrecpush_end
//knsigsearch
struct simple_rec_ex {
public:
	static void load(uint32_t sig_size, uint8_t*& buff, uint32_t& cur_off);
public:
	uint32_t f_first4;
	uint32_t f_crc1;
	uint16_t f_off2;
	uint16_t f_len2;
	uint32_t f_crc2;
	uint32_t f_flags;
	//
	uint32_t f_recid;
	uint32_t f_cureoff;
	uint32_t f_start;
	uint32_t f_stop;
};

struct simple_rec {
public:
	static void load(uint32_t sig_size, uint8_t*& buff, uint32_t& cur_off);
public:
	uint16_t f_off1;
	uint16_t f_len1;
	uint32_t f_crc1;
	uint16_t f_off2;
	uint16_t f_len2;
	uint32_t f_crc2;
	uint32_t f_flags;
	uint32_t f_recid;
	uint32_t f_cureoff;
};

struct poly_vir {
public:
	static void load(uint32_t sig_size, uint8_t*& buff, uint32_t& cur_off);
public:
	uint8_t sig[16];
	uint16_t crc1_off;
	uint16_t crc1_len;
	uint32_t crc1;
	uint16_t crc2_off;
	uint16_t crc2_len;
	uint32_t crc2;
	uint32_t recid;
	uint32_t cureofs;
};

struct vdll_t {
public:
	static void load(uint32_t sig_size, uint8_t*& buff, uint32_t& cur_off, signature_type type);
public:
	signature_type type;
};

struct PCodeValidatorSig_t {
public:
	static void load(uint32_t sig_size, uint8_t*& buff, uint32_t& cur_off);
public:
	uint32_t flags;
	// ProcessedLuaScript* OpaqueLuaScript;
};

struct LuaStandalone_t {
public:
	static void load(uint32_t sig_size, uint8_t*& buff, uint32_t& cur_off);

	// ProcessedLuaScript* OpaqueLuaScript;
};

struct t_full_threat_record {
public:
	std::string name;
	uint32_t threat_id;
	uint16_t flags;
	uint32_t category;
	uint8_t Severity;
	uint8_t Action;
	uint16_t ShortDescriptionID;
	uint16_t AdviceDescription;
};

uint64_t UnpackVirusName(char* cname, char* uname);
void write_format_db();
void write_file(uint8_t* buff, uint64_t size, const char* name);

uint8_t* delta_patch(std::vector<uint8_t>& outfile, size_t* outSize, uint8_t* delta, uint8_t* base);