#ifndef LIBTCG_H
#define LIBTCG_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void translate(char *buffer, size_t size, uint64_t virtual_address);

#ifdef __cplusplus
}
#endif

#endif /* LIBTCG_H */
