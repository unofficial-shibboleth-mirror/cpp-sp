#include "shib-target.h"

main()
{
  char* init = getenv("SHIBCONFIG");
  shib_target_initialize("Test App", init);
}
