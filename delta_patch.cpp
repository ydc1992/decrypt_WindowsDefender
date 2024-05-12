#include "signature.h"

typedef struct delta_blob
{
	unsigned int mergeSize;
	unsigned int mergeCrc;
	unsigned char data_blob[1];
} delta_blob, * pdelta_blob;

uint8_t* get_delta_blob_sig(uint8_t* dt_data)
{
	common_header* entry_delta = (common_header*)dt_data;
	return (uint8_t*)(dt_data + entry_delta->size + 4);
}

char GetMSB(short num)
{
	short msb;
	msb = 1 << (sizeof(num) * 8 - 1);
	if (num & msb)
	{
		return 1;
	}
	return 0;
}

uint8_t* delta_patch(std::vector<uint8_t>& outfile, size_t* outSize, uint8_t* delta, uint8_t* base) {
	size_t index = 0;
	uint8_t* databuf = NULL;

	size_t databuf_size = 0;
	common_header* entry_delta_blob = (common_header*)get_delta_blob_sig(delta);

	unsigned short sizeX = 0;
	size_t cSize = 0;
	size_t blob_size = 0;
	delta_blob* blob;
	if (entry_delta_blob->size == 0xFFFFFF) {
		blob_size = *(uint32_t*)((char*)entry_delta_blob + 4);
		blob = (delta_blob*)((char*)entry_delta_blob + 8);
	}
	else {
		blob_size = entry_delta_blob->size;
		blob = (delta_blob*)((char*)entry_delta_blob + 4);
	}

	unsigned char* deta_blob = blob->data_blob;
	databuf = (unsigned char*)&outfile[0];
	do
	{
		sizeX = *(unsigned short*)(deta_blob + index);
		index += 2;
		if (GetMSB(sizeX)) {
			unsigned int offset = *(unsigned int*)(deta_blob + index);
			cSize = (sizeX & 0x7fff) + 6;
			memcpy(databuf + databuf_size, base + offset, cSize);
			databuf_size += cSize;
			index += 4;
		}
		else {
			memcpy(databuf + databuf_size, deta_blob + index, sizeX);
			databuf_size += sizeX;
			index += sizeX;
		}
	} while (index < blob_size - 8);

	*outSize = databuf_size;
	return databuf;
}