#pragma once
#include <string>
#include <list>
#include <unordered_map>
#include <velocypack/vpack.h>
#include <velocypack/velocypack-aliases.h>
#include <shared_mutex>
#include <cpr/cpr.h>
#include "pulsar/Client.h"
#include "pulsar/Reader.h"

namespace auth {

struct GdnAttributes {
  std::string gdnTenant;
  std::string gdnUrl;
  std::string gdnFabric;
  std::string gdnKey;
  std::string gdnStreamUrl;

  void serialize(VPackBuilder& builder);
  std::string toString() const;

};

struct OsAttributes {
  std::string             osUrl;
  std::string             osTag;
  std::set<std::string>   allowedBuckets;

  void serialize(VPackBuilder& builder);
  std::string toString() const;

};


struct AuthValidateInfo {
  uint64_t role = 0;
  uint64_t expiresAt = 0;
  std::string id; // key-id if it is a APIKey validation.
  std::string tenant;
  std::list<GdnAttributes> authTenants;
  std::list<OsAttributes> authOs;

  bool valid = false; //indicates whether validation success or failure
  std::string failureReason;  // if validation is failed, indicates the validation failure reason.

  std::string toString() const;
  static AuthValidateInfo generateFailed(const std::string& failureReason);
};

struct AuthTenant {
  std::string tenant;
  std::list<GdnAttributes>  authTenants;
  std::list<OsAttributes>   authOs;
  std::set<std::string>     services;
  std::string toString() const;
};

struct AuthConfig {
  std::string serviceId;
  std::string authUrl;
  std::string serviceAuthKey;
  int httpTimeoutSec = 30;
};

class AuthValidator {
public:
  AuthValidator();
  //initialize the AuthValidator, returns pair. first value is sucess status and second value is failure reason if failed.
  std::pair<bool, std::string> initialize(const AuthConfig& clientConfig);

  //Sets a callback method to be notified if tenant data is changed.
  //first parameter of the callback is tenant details and second parameter is whether the tenant is deleted
  void setTenantChangeCallBack(std::function<void(const AuthTenant&, bool)> callback);

  //get Tenants for this service. Tenants are stored in the first output argument
  //returns pair. first value is sucess status and second value is failure reason if failed.
  std::pair<bool, std::string> getTenantsForService(std::list<AuthTenant>& tenants);


  //Validation methods. Returns an AuthValidateInfo.
  //validation is passed only if AuthValidateInfo::valid is true.
  AuthValidateInfo validate(const std::string& type, const std::string& key);
  AuthValidateInfo validateApiKey(const std::string& key);
  AuthValidateInfo validateBearer(const std::string& token);
  AuthValidateInfo validateService(const std::string& serviceApiKey);

  const AuthConfig& getAuthConfig() const { return authConfig_; }
private:
  std::pair<bool, std::string> authenticateWithAuthService();
  AuthValidateInfo validateApiKeywithAuthService(const std::string& key);
  AuthValidateInfo parseApiKeyValidationResponse(VPackSlice resData);
  AuthValidateInfo parseBearerValidationResponse(VPackSlice resData);
  bool extractAuthTenants(const std::string& tenantKey, VPackSlice input, std::list<GdnAttributes>& authTenants);
  bool extractAuthOs(const std::string& tenantKey, VPackSlice input, std::list<OsAttributes>& authOs);
  bool extractServices(const std::string& tenantKey, VPackSlice input, std::set<std::string>& services);
  std::pair<bool, std::string> subscribeToStreams();

  std::pair<bool, AuthValidateInfo> getApiKeyFromCache(const std::string& key);
  void putApiKeyInCache(const std::string& key, const AuthValidateInfo& info);
  bool removeApiKeyByKeyId(const std::string& keyId);

  void onTenantChange(const std::string& msg);
  void onUserChange(const std::string& msg);
  void onApiKeyChange(const std::string& msg);

  static uint64_t getCurrentEpochTimeInSec();

protected:
  AuthConfig                                        authConfig_;
  std::function<void(const AuthTenant& , bool)>     tenantChangeCallback_;
  std::list<GdnAttributes>                          serviceAuthTenants_;
  std::shared_ptr<pulsar::Client>                   pulsarClientPtr_;
  cpr::SslOptions                                   authClientSslOpts_;

  std::shared_mutex                                 apiKeyCacheLock_; //protects apiKeyCache_ and apiKeyIdToKeyMap_
  std::unordered_map<std::string, AuthValidateInfo> apiKeyCache_;
  std::unordered_map<std::string, std::string>      apiKeyIdToKeyMap_;
};

}
