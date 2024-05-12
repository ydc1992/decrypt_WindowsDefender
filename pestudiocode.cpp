//ida F5µÄÎ±´úÂë

#include <cstdint>
#include <cstdio>
#include "pestudio.h"
#include <tchar.h>

uint64_t RVAToFileOffset(unsigned __int8* Sections, unsigned __int16 SecNum, unsigned int RVA)
{
	unsigned __int16 v3; // r9
	__int64 v6; // r8
	unsigned int v7; // edx

	v3 = 0;
	if (!SecNum)
		return -1i64;
	while (1)
	{
		v6 = 40 * (unsigned int)v3;
		v7 = *(uint32_t*)&Sections[v6 + 12];
		if (RVA >= v7 && RVA < v7 + *(uint32_t*)&Sections[v6 + 16])
			break;
		if (++v3 >= SecNum)
			return -1i64;
	}
	return RVA + *(uint32_t*)&Sections[v6 + 20] - v7;
}

__int64   return_entry(FILE* modid, pe_resource_data_entry_t* res, unsigned __int64 res_fofs) {
	fseek(modid, res_fofs, 0);
	int Buffer[4];
	fread(Buffer, 1, 0x10, modid);
	res->OffsetToData = Buffer[0];
	res->Size = Buffer[1];
	res->CodePage = Buffer[2];
	res->Reserved = Buffer[3];
	return 0;
}

int  query_level_res(rparser_vars_t* r, unsigned __int64 rdir_fofs, unsigned __int8 level) {
	unsigned __int64 v6; // r14
	int v7; // r12d
	int v8; // eax
	resquery_t* rquery; // rcx
	__int64 v10; // rbp
	unsigned __int64 base_fofs;
	__int64 v15; // r15
	unsigned __int64 v16; // r15
	const wchar_t* v17; // rcx
	char* v18; // r8
	int v24; // [rsp+70h] [rbp+18h]

LABEL_1:

	if (level >= 3)
		return -1;
	fseek(r->modid, rdir_fofs, 0);
	if (fread(r->_tmp, 1, 0x10, r->modid) != 16) {
		return -1;
	}
	v6 = rdir_fofs + 16;
	v7 = 0;
	v8 = *(unsigned __int16*)&r->_tmp[14] + *(unsigned __int16*)&r->_tmp[12];
	v24 = v8;
	while (1)
	{
		if (v7 >= v8)
			return 1;
		fseek(r->modid, v6, 0);
		if (fread(r->_tmp, 1, 8, r->modid) != 8) {
			return 1;
		}
		rquery = r->rquery;
		v6 += 8i64;
		rdir_fofs = *(unsigned int*)r->_tmp;
		v10 = *(unsigned int*)&r->_tmp[4];
		if (rquery->Name[level])
		{
			if ((rdir_fofs & 0x80000000) == 0)
				goto LABEL_27;
			fseek(r->modid, (rdir_fofs & 0xFFFFFFFF7FFFFFFF) + r->base_fofs, 0);

			if (fread(r->_tmp, 1, 2, r->modid) != 2) {
				return -1;
			}
			v15 = *(unsigned __int16*)r->_tmp;
			if ((unsigned int)v15 > 0x78)
				v15 = 120i64;
			fseek(r->modid, r->base_fofs + (rdir_fofs & 0xFFFFFFFF7FFFFFFF) + 2, 0);
			v16 = 2 * v15;
			if (fread(r->_tmp, 1, v16, r->modid) != v16)
			{
				return -1;
			}
			*(uint16_t*)&r->_tmp[v16] = 0;
			v17 = r->rquery->Name[level];
			v18 = (char*)((char*)r->_tmp - (char*)v17);
			if (_wcsicmp((wchar_t*)r->_tmp, v17)) {
				goto LABEL_27;
			}

			base_fofs = r->base_fofs;
			if ((int)v10 >= 0)
				return return_entry(r->modid, r->res, r->base_fofs + v10);
			++level;
			rdir_fofs = r->base_fofs + v10 & 0x7FFFFFFF;
			goto LABEL_1;
		}
		else
		{
			if (rquery->Id[level] == (unsigned __int16)rdir_fofs) {
				base_fofs = r->base_fofs;
				if ((int)v10 >= 0)
					return return_entry(r->modid, r->res, r->base_fofs + v10);
				++level;
				rdir_fofs = r->base_fofs + v10 & 0x7FFFFFFF;
				goto LABEL_1;
			}
			if (rquery->Id[level] != -1)
				goto LABEL_27;
			if (level == 2) {
				base_fofs = r->base_fofs;
				if ((int)v10 >= 0)
					return return_entry(r->modid, r->res, r->base_fofs + v10);
				++level;
				rdir_fofs = r->base_fofs + v10 & 0x7FFFFFFF;
				goto LABEL_1;
			}
			goto LABEL_27;
		}

	LABEL_27:
		v8 = v24;
		++v7;
	}
	return -1;
}

int64_t  FindResourceOffset(FILE* fp, uint64_t StartOffset, uint8_t* Header, resquery_t* rquery, pe_resource_data_entry_t* res) {
	rparser_vars_t r;

	uint8_t Buffer[24];
	auto v5 = *(uint32_t*)(Header + 0x3c);
	auto  v9 = StartOffset + v5;
	fseek(fp, v9, 0);
	fread(Buffer, 1, 0x18, fp);
	if (*(uint32_t*)Buffer != 0x4550)
		return -1;
	auto v10 = *(uint16_t*)&Buffer[6];
	if (*(uint16_t*)&Buffer[6] >= 0x10)
		return -1;
	auto v11 = *(uint16_t*)&Buffer[20] + 24 + v9;
	fseek(fp, v11 - 0x70, 0);
	int v18[16] = {};
	fread(v18, 1, 8, fp);

	r.base_fofs = (unsigned int)v18[0];
	fseek(fp, v11, 0);

	uint8_t Sections[640];
	fread(Sections, 1, 40 * (unsigned int)v10, fp);
	auto v12 = RVAToFileOffset(Sections, v10, r.base_fofs);

	r.base_fofs = (unsigned int)StartOffset + v12;
	r.modid = fp;
	r.rquery = rquery;
	r.res = res;
	query_level_res(&r, r.base_fofs, 0);
	auto  v14 = RVAToFileOffset(Sections, v10, res->OffsetToData);
	return StartOffset + v14;
}