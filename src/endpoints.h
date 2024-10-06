#ifndef CFORUM_ENDPOINTS_INCLUDED
#define CFORUM_ENDPOINTS_INCLUDED

#include "http.h"

void init_endpoints(void);
void free_endpoints(void);
void respond(Request request, ResponseBuilder *b);

#endif // CFORUM_ENDPOINTS_INCLUDED