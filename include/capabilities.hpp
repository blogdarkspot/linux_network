#ifndef __CAPABILITIES_HPP__
#define __CAPABILITIES_HPP__
#include <sys/capability.h>
#include <system_error>
#include <pwd.h>
#include <shadow.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>

namespace security
{
static std::error_code
authenticate_user (const char *__username, const char *__password)
{
  auto pwd = getpwnam (__username);
  if (pwd == nullptr)
    {
      return std::error_code (errno, std::system_category ());
    }
  auto spwd = getspnam (__username);
  if (spwd == nullptr)
    {
      return std::error_code (errno, std::system_category ());
    }
  if (spwd != nullptr)
    {
      pwd->pw_passwd = spwd->sp_pwdp;
    }
  auto encrypted = crypt (__password, pwd->pw_passwd);

  auto authOk = strcmp (encrypted, pwd->pw_passwd) == 0;

  if (!authOk)
    {
      return std::error_code (EACCES, std::system_category ());
    }
  return std::error_code ();
}
};

namespace security::capabilities {

static std::error_code enable_net_raw()
{
    cap_t caps = cap_get_proc();
    if (caps == nullptr)
    {
        return std::error_code(errno, std::system_category());
    }

    cap_value_t cap_list[1] = {CAP_NET_RAW};
    if (cap_set_flag(caps, CAP_EFFECTIVE, 1, cap_list, CAP_SET) == -1)
    {
        cap_free(caps);
        return std::error_code(errno, std::system_category());
    }

    if (cap_set_flag(caps, CAP_PERMITTED, 1, cap_list, CAP_SET) == -1)
    {
        cap_free(caps);
        return std::error_code(errno, std::system_category());
    }

    if (cap_set_proc(caps) == -1)
    {
        cap_free(caps);
        return std::error_code(errno, std::system_category());
    }

    cap_free(caps);
    return std::error_code();

};
}
#endif