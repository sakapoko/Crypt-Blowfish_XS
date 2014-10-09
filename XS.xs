#define PERL_NO_GET_CONTEXT 1
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

MODULE = Crypt::Blowfish::XS             PACKAGE = Crypt::Blowfish::XS

#define CRYPT_OUTPUT_SIZE (7 + 22 + 31 + 1)
#define CRYPT_GENSALT_OUTPUT_SIZE (7 + 22 + 1)

SV*
_crypt_blowfish(key, settings)
const char *key;
const char *settings;
PREINIT:
  char output[CRYPT_OUTPUT_SIZE];
PPCODE:
  _crypt_blowfish_rn(key, settings, output, sizeof(output));
  ST(0) = sv_2mortal(newSVpv(output, 0));
  XSRETURN(1);

SV*
_crypt_gensalt(prefix, count, input, size)
const char *prefix;
unsigned long count;
const char *input;
int size;
PREINIT:
  char output[CRYPT_GENSALT_OUTPUT_SIZE];
PPCODE:
  _crypt_gensalt_blowfish_rn(prefix, count, input, size, output, sizeof(output));
  ST(0) = sv_2mortal(newSVpv(output, 0));
  XSRETURN(1);

