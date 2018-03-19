#include "pdb.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

// http://www.psdevwiki.com/ps3/Project_Database_(PDB)

unsigned int pdb_len_theme_01 = 210;
static const unsigned char pdb_01_theme[] = {0, 0, 0, 0, 100, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 101, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0, 2, 0, 0, 0, 102, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 107, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0, 12, 0, 0, 0, 104, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 108, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0, 1, 0, 0, 0, 109, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0, 110, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 112, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 113, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 114, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 115, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 116, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 111, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0};

unsigned int pdb_len_theme_02 = 41;
static const unsigned char pdb_02_theme[] = {230, 0, 0, 0, 29, 0, 0, 0, 29, 0, 0, 0, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32};

unsigned int pdb_len_theme_03 = 95;
static const unsigned char pdb_03_theme[] = {218, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 206, 0, 0, 0, 8, 0, 0, 0, 8, 0, 0, 0, 0, 144, 1, 0, 0, 0, 0, 0, 208, 0, 0, 0, 8, 0, 0, 0, 8, 0, 0, 0, 0, 144, 1, 0, 0, 0, 0, 0, 204, 0, 0, 0, 30, 0, 0, 0, 30, 0, 0, 0, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32};

unsigned int pdb_len_theme_04 = 65;
static const unsigned char pdb_04_theme[] = {232, 0, 0, 0, 120, 0, 0, 0, 120, 0, 0, 0, 2, 0, 0, 0, 31, 0, 0, 0, 14, 0, 0, 128, 13, 0, 0, 0, 16, 15, 0, 0, 0, 0, 0, 0, 0, 144, 1, 0, 0, 0, 0, 0, 0, 144, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

unsigned int pdb_len_theme_05 = 133;
static const unsigned char pdb_05_theme[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 205, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 236, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0, 199, 8, 120, 149, 237, 0, 0, 0, 32, 0, 0, 0, 32, 0, 0, 0, 191, 31, 176, 182, 101, 19, 244, 6, 161, 144, 115, 57, 24, 86, 53, 208, 34, 131, 37, 93, 67, 148, 147, 158, 117, 166, 119, 106, 126, 3, 133, 198};


static uint8_t *putStringParam(uint8_t *buffer, uint32_t code, const char *string) {
    //Include terminating zero char
    uint32_t len = strlen(string) + 1;
    *((uint32_t *) buffer) = code;
    buffer += sizeof(uint32_t);
    *((uint32_t *) buffer) = len;
    buffer += sizeof(uint32_t);
    *((uint32_t *) buffer) = len;
    buffer += sizeof(uint32_t);
    memcpy(buffer, string, len);
    return buffer + len;
}

size_t writeFile(const char *path, const uint8_t *buf, const uint32_t length) {
    FILE *out = fopen(path, "wb");
    if (out) {
        if (length > 0) {
            size_t written = fwrite(buf, sizeof(uint8_t), length, out);
            fclose(out);
            return written;
        } else {
            fclose(out);
            return 1;
        }
    }
    return 0;
}

uint32_t pkgdbGenerate(uint8_t *buffer, uint32_t length, char *title, char *titleid, char *contentid, const char *pkg_name, char *pkg_url, uint32_t install_id) {
    // printf("PDB_GEN(0x%p, %u, 0x%p, 0x%p, 0x%p, 0x%p, %llu, %u)\n", buffer, length, title, titleid, pkg_name, pkg_url, pkg_size, install_id);
    if (!title) title = "DLC ready for installation";
    if (!titleid) titleid = "UNKN00000";
    if (!pkg_name) pkg_name = "pkg.pkg";
    if (!pkg_url) pkg_url = "https://example.com/pkg.pkg";
	if (!contentid) contentid = "EP9000-PCSF00688_00-P000000000002912";
	// it's wrong by a few bytes... (doesn't really matter...)
    uint32_t total = pdb_len_theme_01 +
                     13 + strlen(title) +
                     13 + strlen(pkg_name) +
                     13 + strlen(pkg_url) +
                     13 + 0x1D + //For icon path
					 13 + strlen(contentid) +
                     pdb_len_theme_02 +
					 13 + strlen(titleid) +
					 pdb_len_theme_03 +
					 13 + strlen(contentid) +
					 pdb_len_theme_04 + pdb_len_theme_05;
	// printf("\nThe calculated size is %lu", total);
	if (total < length) {
        uint8_t *start = buffer;
        memcpy(buffer, pdb_01_theme, pdb_len_theme_01);
        buffer += pdb_len_theme_01;

        buffer = putStringParam(buffer, 0x69, title);

        buffer = putStringParam(buffer, 0xCB, pkg_name);

        buffer = putStringParam(buffer, 0xCA, pkg_url);

        char icon_path[0x20];
        snprintf(icon_path, 0x20, "ux0:bgdl/t/%08d/icon.png", install_id);
        buffer = putStringParam(buffer, 0x6A, icon_path);
		// add empty stuff...
		memcpy(buffer, pdb_02_theme, pdb_len_theme_02);
		buffer += pdb_len_theme_02;

		buffer = putStringParam(buffer, 0xD9, contentid);
		// add unknown stuff to buffer...
        memcpy(buffer, pdb_03_theme, pdb_len_theme_03);
        buffer += pdb_len_theme_03;

		// add titleid:
		buffer = putStringParam(buffer, 0xDC, titleid);

		// add unknown stuff to buffer....
        memcpy(buffer, pdb_04_theme, pdb_len_theme_04);
		buffer += pdb_len_theme_04;

		// add titleid (directly, not via function...)
		memcpy(buffer, titleid, strlen(titleid));
		buffer += strlen(titleid);

		// the rest:

		memcpy(buffer, pdb_05_theme, pdb_len_theme_05);
		buffer += pdb_len_theme_05;
        return buffer - start;
    }
    return 0;
}

