#include "photoniq_auth_client/AuthRestClient.h"
#include <cpr/cpr.h>

using namespace auth;

AuthRestResponse AuthRestClient::createTenant(const AuthValidator& client, const std::string& tenantKey,
                                              GdnAttributes gdnattrbs, bool addGdnAttrbs,
                                              OsAttributes osAttrss, bool addOsAttrbs, const std::string& service) {
  std::string url = client.getAuthConfig().authUrl + "/v1/tenants";
  cpr::Header headers = {{"Authorization", "apikey " + client.getAuthConfig().serviceAuthKey}};


  VPackBuilder builder;
  builder.openObject();
  builder.add("tenant_key", VPackValue(tenantKey));

  if (addGdnAttrbs) {
    builder.add("auth_tenants", VPackValue(VPackValueType::Array));
    gdnattrbs.serialize(builder);
    builder.close(); //auth_tenants
  }
  if (addOsAttrbs) {
    builder.add("auth_os", VPackValue(VPackValueType::Array));
    osAttrss.serialize(builder);
    builder.close(); //auth_tenants
  }

  builder.add("services", VPackValue(VPackValueType::Array));
  builder.add(VPackValue(service));
  builder.close(); //services

  builder.close();

  cpr::Response cprRes = cpr::Post(cpr::Url{url},
                               cpr::Body{builder.toJson()},
                               headers,
                               cpr::Timeout{client.getAuthConfig().httpTimeoutSec * 1000},
                               cpr::Ssl(cpr::ssl::VerifyPeer{false}));

  return AuthRestResponse{(int)cprRes.status_code, cprRes.reason, cprRes.text};
}

AuthRestResponse AuthRestClient::deleteTenant(const AuthValidator& client, const std::string& tenantKey) {
  std::string url = client.getAuthConfig().authUrl + "/v1/tenants/" + tenantKey;
  cpr::Header headers = {{"Authorization", "apikey " + client.getAuthConfig().serviceAuthKey}};

  cpr::Response cprRes = cpr::Delete(cpr::Url{url},
                               headers,
                               cpr::Timeout{client.getAuthConfig().httpTimeoutSec * 1000},
                               cpr::Ssl(cpr::ssl::VerifyPeer{false}));

  return AuthRestResponse{(int)cprRes.status_code, cprRes.reason, cprRes.text};
}

AuthRestResponse AuthRestClient::createApiKey(const AuthValidator& client, const std::string& keyId, bool enabled, uint64_t role,
                                              const std::string& tenantKey, const std::string& ttl) {
  std::string url = client.getAuthConfig().authUrl + "/v1/apikeys";
  cpr::Header headers = {{"Authorization", "apikey " + client.getAuthConfig().serviceAuthKey}};


  VPackBuilder builder;
  builder.openObject();
  builder.add("keyid", VPackValue(keyId));
  builder.add("enabled", VPackValue(enabled));
  builder.add("role", VPackValue(role));
  builder.add("tenant_key", VPackValue(tenantKey));
  builder.add("ttl", VPackValue(ttl));
  builder.close();

  cpr::Response cprRes = cpr::Post(cpr::Url{url},
                               cpr::Body{builder.toJson()},
                               headers,
                               cpr::Timeout{client.getAuthConfig().httpTimeoutSec * 1000},
                               cpr::Ssl(cpr::ssl::VerifyPeer{false}));

  return AuthRestResponse{(int)cprRes.status_code, cprRes.reason, cprRes.text};
}

AuthRestResponse AuthRestClient::deleteApiKey(const AuthValidator& client, const std::string& keyId) {
  std::string url = client.getAuthConfig().authUrl + "/v1/apikeys/" + keyId;
  cpr::Header headers = {{"Authorization", "apikey " + client.getAuthConfig().serviceAuthKey}};

  cpr::Response cprRes = cpr::Delete(cpr::Url{url},
                               headers,
                               cpr::Timeout{client.getAuthConfig().httpTimeoutSec * 1000},
                               cpr::Ssl(cpr::ssl::VerifyPeer{false}));

  return AuthRestResponse{(int)cprRes.status_code, cprRes.reason, cprRes.text};
}

AuthRestResponse AuthRestClient::createUser(const AuthValidator& client, const std::string& email, const std::string& password,
                                            uint64_t role, const std::string& tenantKey) {
  std::string url = client.getAuthConfig().authUrl + "/v1/users";
  cpr::Header headers = {{"Authorization", "apikey " + client.getAuthConfig().serviceAuthKey}};


  VPackBuilder builder;
  builder.openObject();
  builder.add("email", VPackValue(email));
  builder.add("password", VPackValue(password));
  builder.add("role", VPackValue(role));

  builder.add("tenant_keys", VPackValue(VPackValueType::Array));
  builder.add(VPackValue(tenantKey));
  builder.close();

  builder.close();

  cpr::Response cprRes = cpr::Post(cpr::Url{url},
                               cpr::Body{builder.toJson()},
                               headers,
                               cpr::Timeout{client.getAuthConfig().httpTimeoutSec * 1000},
                               cpr::Ssl(cpr::ssl::VerifyPeer{false}));

  return AuthRestResponse{(int)cprRes.status_code, cprRes.reason, cprRes.text};
}

AuthRestResponse AuthRestClient::deleteUser(const AuthValidator& client, const std::string& email) {
  std::string url = client.getAuthConfig().authUrl + "/v1/users/" + email;
  cpr::Header headers = {{"Authorization", "apikey " + client.getAuthConfig().serviceAuthKey}};

  cpr::Response cprRes = cpr::Delete(cpr::Url{url},
                               headers,
                               cpr::Timeout{client.getAuthConfig().httpTimeoutSec * 1000},
                               cpr::Ssl(cpr::ssl::VerifyPeer{false}));

  return AuthRestResponse{(int)cprRes.status_code, cprRes.reason, cprRes.text};
}

AuthRestResponse AuthRestClient::createBearerToken(const AuthValidator& client, const std::string& email, const std::string& password) {
  std::string url = client.getAuthConfig().authUrl + "/v1/bearer";
  cpr::Header headers = {{"Authorization", "apikey " + client.getAuthConfig().serviceAuthKey}};


  VPackBuilder builder;
  builder.openObject();
  builder.add("email", VPackValue(email));
  builder.add("password", VPackValue(password));
  builder.close();

  cpr::Response cprRes = cpr::Post(cpr::Url{url},
                               cpr::Body{builder.toJson()},
                               headers,
                               cpr::Timeout{client.getAuthConfig().httpTimeoutSec * 1000},
                               cpr::Ssl(cpr::ssl::VerifyPeer{false}));

  return AuthRestResponse{(int)cprRes.status_code, cprRes.reason, cprRes.text};
}



