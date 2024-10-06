#ifndef CFORUM_CONFIG_INCLUDED
#define CFORUM_CONFIG_INCLUDED

#include <stdint.h>
#include "basic.h"

void     config_init(void);
void     config_free(void);
bool     config_load(string file);
uint32_t config_int(string name);
bool     config_bool(string name);
string   config_string(string name);

#endif // CFORUM_CONFIG_INCLUDED