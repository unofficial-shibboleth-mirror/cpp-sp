#include "shib-target.h"

main()
{
  char* init = getenv("SHIBCONFIG");
  char* app = getenv("SHIBTESTAPP");
  shib_target_initialize((app ? app : "Test App"), init);
}
