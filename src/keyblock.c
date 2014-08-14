/**
 * Copyright (C) 2009-2013 OSCam developers
 * Copyright (c) 2014 Iwan Timmer
 * 
 * This file is part of VMCam.
 * 
 * VMCam is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * VMCam is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with VMCam.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <time.h>
#include <stdio.h>
#include <string.h>

#include <openssl/aes.h>

#include "keyblock.h"
#include "log.h"

#define OFFSET_MKEY1 4
#define OFFSET_MKEY2 56
#define OFFSET_EXPIRE_MKEY1 36
#define OFFSET_EXPIRE_MKEY2 88

#define OFFSET_CWKEYS 33

#define touInt16(__data) (((&__data)[1] << 8) | __data)

char * f_keyblock;

time_t parse_ts(unsigned char * data) {
	struct tm t;
	time_t t_of_day;
	t.tm_year = touInt16(data[0]) - 1900; //2014-1900
	t.tm_mon = touInt16(data[2]) - 1; // Month, 0 - jan
	t.tm_mday = touInt16(data[4]); // Day of the month
	t.tm_hour = touInt16(data[6]);
	t.tm_min = touInt16(data[8]);
	t.tm_sec = touInt16(data[10]);
	t.tm_isdst = -1; // Is DST on? 1 = yes, 0 = no, -1 = unknown
	t_of_day = mktime(&t);

	return t_of_day;
}

int32_t keyblock_analyse_file(unsigned char * dcw, unsigned char * ECM) {
	FILE *fp;
	unsigned char token[108];
	unsigned char * mkey;
	uint32_t t = 0;
	AES_KEY aesmkey;
	unsigned char table = ECM[0];
	uint16_t channel = (ECM[18] << 8) + ECM[19];
	time_t time_now, time_mkey1, time_mkey2;
	char valid_till_str[64];
	fp = fopen(f_keyblock, "r");
	if (!fp) {
		LOG(ERROR, "[KEYBLOCK] Could not open file %s", f_keyblock);
		return (0);
	}
	LOG(INFO, "[KEYBLOCK] Find control word for Channel %d table 0x%02X", channel, table);

	fseek(fp, 4, SEEK_SET);
	while (fread(token, 108, 1, fp)) {
		if ((uint16_t) ((token[t + 1] << 8) + token[t]) == channel) {
			time_now = time(NULL);
			time_mkey1 = parse_ts(token + OFFSET_EXPIRE_MKEY1);
			time_mkey2 = parse_ts(token + OFFSET_EXPIRE_MKEY2);
			LOG(DEBUG, "[KEYBLOCK] Master keys found for Channel: %d. Valid till: %s",	channel, ctime_r(&time_mkey2, valid_till_str));

			if (difftime(time_mkey1, time_now) > 0) { // Check expire date mkey 1
				LOG(DEBUG, "[KEYBLOCK] Master key 1 selected");
				mkey = token + OFFSET_MKEY1;
			} else {
				if (difftime(time_mkey2, time_now) > 0) { // Check expire date mkey 2
					LOG(DEBUG, "[KEYBLOCK] Master key 2 selected");
					if (difftime(time_mkey2, time_now) < 86400) {
						LOG(DEBUG, "[KEYBLOCK] Warning: Master keys for Channel: %d will expire in %d minutes",	channel, (int)difftime(time_mkey2, time_now) / 60);
					}
					mkey = token + OFFSET_MKEY2;
				} else {
					LOG(INFO, "[KEYBLOCK] Keyblock is to old\n");
					return 0;
				}
			}
			LOG(VERBOSE, "[KEYBLOCK] AES Key %x %x %x %x %x %x", mkey[0], mkey[1], mkey[2], mkey[3], mkey[4]);
			AES_set_decrypt_key(mkey, 128, &aesmkey);

			for (t = 0; t < 48; t += 16) {
				AES_ecb_encrypt(&ECM[24 + t], &ECM[24 + t], &aesmkey,
				AES_DECRYPT);
			}
			
			LOG(VERBOSE, "[KEYBLOCK] ECM %x %x %x %x %x %x", ECM[0], ECM[1], ECM[2], ECM[3], ECM[4], ECM[5]);
			LOG(VERBOSE, "[KEYBLOCK] Key 1 %x %x %x %x %x %x", ECM[0+OFFSET_CWKEYS], ECM[1+OFFSET_CWKEYS], ECM[2+OFFSET_CWKEYS], ECM[3+OFFSET_CWKEYS], ECM[4+OFFSET_CWKEYS], ECM[5+OFFSET_CWKEYS]);
			LOG(VERBOSE, "[KEYBLOCK] Key 2 %x %x %x %x %x %x", ECM[0+OFFSET_CWKEYS+16], ECM[1+OFFSET_CWKEYS+16], ECM[2+OFFSET_CWKEYS+16], ECM[3+OFFSET_CWKEYS+16], ECM[4+OFFSET_CWKEYS+16], ECM[5+OFFSET_CWKEYS+16]);

			
			if (memcmp(&ECM[24], "CEB", 3) == 0) {
				LOG(VERBOSE, "[KEYBLOCK] Check %x %x %x", ECM[24], ECM[25], ECM[26]);
				LOG(DEBUG, "[KEYBLOCK] ECM decrypt check passed");
			} else {
				LOG(ERROR, "[KEYBLOCK] ECM decrypt failed, wrong master key or unknown format");
				fclose(fp);
				return 0;
			}
			if (table == 0x80) {
				memcpy(dcw, ECM + OFFSET_CWKEYS, 32);
			} else {
				memcpy(dcw, ECM + OFFSET_CWKEYS + 16, 16);
				memcpy(dcw + 16, ECM + OFFSET_CWKEYS, 16);
			}
			fclose(fp);
			return 1;
		}
	}
	LOG(ERROR, "[KEYBLOCK] No Master key found for channel: %d, cannot decrypt ECM", channel);
	fclose(fp);
	return 0;
}
