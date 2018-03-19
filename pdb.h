#include <stdint.h>
#include <stddef.h>
size_t writeFile(const char *path, const uint8_t *buf, const uint32_t length);
uint32_t pkgdbGenerate(uint8_t *buffer, uint32_t length, char *title, char *titleid, char *contentid, const char *pkg_name, char *pkg_url, uint32_t install_id);