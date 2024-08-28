#pragma once
#include <string>
#include "AuthValidator.h"

namespace auth {

struct AuthRestResponse {
  int statusCode = 0;
  std::string reason;
  std::string responseBody;
};

class AuthRestClient {
public:
  AuthRestResponse createTenant(const AuthValidator& client, const std::string& tenantKey, GdnAttributes gdnattrbs, bool addGdnAttrbs,
                                OsAttributes osAttrss, bool addOsAttrbs, const std::string& service);
  AuthRestResponse deleteTenant(const AuthValidator& client, const std::string& tenantKey);

  AuthRestResponse createApiKey(const AuthValidator& client, const std::string& keyId, bool enabled, uint64_t role,
                                const std::string& tenantKey, const std::string& ttl);
  AuthRestResponse deleteApiKey(const AuthValidator& client, const std::string& keyId);

  AuthRestResponse createUser(const AuthValidator& client, const std::string& email, const std::string& password,
                                              uint64_t role, const std::string& tenantKey);
  AuthRestResponse deleteUser(const AuthValidator& client, const std::string& email);

  AuthRestResponse createBearerToken(const AuthValidator& client, const std::string& email, const std::string& password);

};
}
