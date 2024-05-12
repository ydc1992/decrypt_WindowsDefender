#pragma once

struct pe_resource_data_entry_t {
	uint32_t OffsetToData;
	uint32_t Size;
	uint32_t CodePage;
	uint32_t Reserved;
};

struct resquery_t {
	uint32_t Id[3];
	const wchar_t* Name[3];
};

struct rparser_vars_t {
	uint8_t _tmp[242];
	FILE* modid;
	resquery_t* rquery;
	pe_resource_data_entry_t* res;
	uint64_t base_fofs;
};

int64_t  FindResourceOffset(FILE* fp, uint64_t StartOffset, uint8_t* Header, resquery_t* rquery, pe_resource_data_entry_t* res);