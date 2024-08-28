#include <photoniq_auth_client/AuthValidator.h>
// #include "../Log.h"


using namespace auth;

std::string GdnAttributes::toString() const {
  std::stringstream ss;
  ss << "GdnAttributes { "
     << "gdnTenant: "     << gdnTenant << ", "
     << "gdnUrl: "        << gdnUrl << ", "
     << "gdnFabric: "     << gdnFabric << ", "
     << "gdnKey: "        << gdnKey << ", "
     << "gdnStreamUrl: "  << gdnStreamUrl
     << " }";
  return ss.str();
}

void GdnAttributes::serialize(VPackBuilder& builder) {
  builder.openObject();
  builder.add("gdn_tenant", VPackValue(gdnTenant));
  builder.add("gdn_url", VPackValue(gdnUrl));
  builder.add("gdn_fabric", VPackValue(gdnFabric));
  builder.add("gdn_key", VPackValue(gdnKey));
  builder.add("gdn_stream_url", VPackValue(gdnStreamUrl));
  builder.close();
}

std::string OsAttributes::toString() const {
  std::stringstream ss;
  ss << "OsAttributes { "
     << "osUrl: "   << osUrl << ", "
     << "osTag: "   << osTag << ", "
     << "allowedBuckets: [";
  for (const auto& bucket : allowedBuckets) {
    ss << bucket << ", ";
  }
  ss << "] }";
  return ss.str();
}

void OsAttributes::serialize(VPackBuilder& builder) {
  builder.openObject();
  builder.add("os_url", VPackValue(osUrl));
  builder.add("os_tag", VPackValue(osTag));
  builder.add("os_allowed_buckets", VPackValue(VPackValueType::Array));
  for (const auto& bucket : allowedBuckets) {
    builder.add(VPackValue(bucket));
  }
  builder.close(); //os_allowed_buckets
  builder.close();
}

std::string AuthTenant::toString() const {
  std::stringstream ss;
  ss << "AuthTenant { "
     << "tenant: " << tenant << ", "
     << "authTenants: [";
  for (const auto& tenant : authTenants) {
    ss << tenant.toString() << ", ";
  }
  ss << "], "
    << "authOs: [";
  for (const auto& os : authOs) {
   ss << os.toString() << ", ";
  }
  ss << "], "
    << "services: [";
  for (const auto& service : services) {
   ss << service << ", ";
  }
  ss << "] }";

  return ss.str();
}

std::string AuthValidateInfo::toString() const {
  std::stringstream ss;
  ss << "AuthValidateInfo { "
     << "valid: "     << valid << ", "
     << "role: "      << role << ", "
     << "expiresAt: " << expiresAt << ", "
     << "id: "        << id << ", "
     << "tenant: "    << tenant << ", "
     << "authTenants: [";
  for (const auto& tenant : authTenants) {
    ss << tenant.toString() << ", ";
  }
  ss << "] ";
  ss << ", osAuth: [";
  for (const auto& osAttr : authOs) {
   ss << osAttr.toString() << ", ";
  }
  ss << "] ";
  if (!failureReason.empty())
    ss << ", failureReason: " << failureReason;
  ss << " }";
  return ss.str();
}

AuthValidateInfo AuthValidateInfo::generateFailed(const std::string& failureReason) {
  AuthValidateInfo res;
  res.valid = false;
  res.failureReason = failureReason;
  return res;
}

AuthValidator::AuthValidator() {
  authClientSslOpts_.verify_peer = false;
}

std::pair<bool, std::string> AuthValidator::initialize(const AuthConfig& clientConfig) {
  authConfig_ = clientConfig;

  auto res = authenticateWithAuthService();
  if (!res.first)
    return res;

  res = subscribeToStreams();
  if (!res.first)
    return res;

  return {true, "OK"};
}

void AuthValidator::setTenantChangeCallBack(std::function<void(const AuthTenant&, bool)> callback) {
    tenantChangeCallback_ = std::move(callback);
}

std::pair<bool, std::string> AuthValidator::getTenantsForService(std::list<AuthTenant>& tenants) {
  std::string url = authConfig_.authUrl + "/v1/tenants/service/" + authConfig_.serviceId;
  cpr::Header headers = {{"Authorization", "apikey " + authConfig_.serviceAuthKey}};
  cpr::Response res = cpr::Get(cpr::Url{url},
                               headers,
                               cpr::Timeout{authConfig_.httpTimeoutSec * 1000},
                               authClientSslOpts_);
  if (res.status_code == 200) {
    if (res.text.empty()) {
      return {false, "Empty response received from Auth service"};
    }
    try {
      VPackParser jsonParser;
      jsonParser.parse(res.text);
      auto slice = jsonParser.builder().slice();
      if (!slice.isArray()) {
        return {false, "Malformed response received from Auth service. Expecting a JSON array"};
      }
      for (auto const& tenantSlice : VPackArrayIterator(slice)) {
        auto keySlice = tenantSlice.get("_key");
        if (!keySlice.isString()) {
          std::cerr << "WARN: AuthValidator:getTenantsForService: '_key' field is not found or not a string in one of the auth_tenants. Ignoring it..";
          continue;
        }
        AuthTenant tenant;
        tenant.tenant = keySlice.copyString();
        if (tenantSlice.hasKey("auth_tenants")) {
          auto authTenantsSlice = tenantSlice.get("auth_tenants");
          if (authTenantsSlice.isArray()) {
            extractAuthTenants(tenant.tenant, authTenantsSlice, tenant.authTenants);
          } else {
            std::cerr << "WARN: AuthValidator:getTenantsForService: Tenant Key : " << tenant.tenant << ", 'auth_tenants' field is not an array";
          }
        }
        if (tenantSlice.hasKey("auth_os")) {
          auto authOsSlice = tenantSlice.get("auth_os");
          if (authOsSlice.isArray()) {
            extractAuthOs(tenant.tenant, authOsSlice, tenant.authOs);
          } else {
            std::cerr << "WARN: AuthValidator:getTenantsForService: Tenant Key : " << tenant.tenant << ", 'auth_os' field is not an array";
          }
        }
        if (tenantSlice.hasKey("services")) {
          auto servicesSlice = tenantSlice.get("services");
          if (servicesSlice.isArray()) {
            extractServices(tenant.tenant, servicesSlice, tenant.services);
          } else {
            std::cerr << "WARN: AuthValidator:getTenantsForService: Tenant Key : " << tenant.tenant << ", 'services' field is not an array";
          }
        }
        tenants.push_back(tenant);
      }
      return {true, "OK"};

    } catch (const VPackException& ex) {
      return {false, "Failed to parse Auth service response. error: " + std::string(ex.what())};
    }

  } else if (res.status_code == 0) {
    return {false, "Failed to connect to Auth service"};
  } else {
    std::stringstream error;
    error << "Getting tenants for service failed with code: " << res.status_code
          << ", reason: " << res.reason << ", response: " << res.text;
    return {false, error.str()};
  }
}

AuthValidateInfo AuthValidator::validate(const std::string& type, const std::string& key) {

  if (type == "apikey") {
    auto cacheRes = getApiKeyFromCache(key);
    if (cacheRes.first) { //cache hit (could be failure as well if expired key)
      return cacheRes.second;
    }
  }

  std::string url = authConfig_.authUrl + "/v1/validate/" + type + "/" + key;
  cpr::Header headers;
  cpr::Response res = cpr::Get(cpr::Url{url},
                               headers,
                               cpr::Timeout{authConfig_.httpTimeoutSec * 1000},
                               authClientSslOpts_);
  if (res.status_code == 200) {
    if (res.text.empty()) {
      return AuthValidateInfo::generateFailed("Empty response received from Auth service");
    }
    try {
      VPackParser jsonParser;
      jsonParser.parse(res.text);
      auto slice = jsonParser.builder().slice();
      if (!slice.isObject()) {
        return AuthValidateInfo::generateFailed("Malformed response received from Auth service. Expecting a JSON Object");
      }
      if (slice.get("SuccessApikey").isObject()) {
        //technically we should check whether the type is 'apikey' here.
        //But leaving it to be same as python implementation
        auto validationRes = parseApiKeyValidationResponse(slice);
        if (validationRes.valid) {
          putApiKeyInCache(key, validationRes);
        }
        return validationRes;

      } else if (slice.get("SuccessBearer").isObject()) {
        //same here: we should check whether the type is 'bearer' here.
        return parseBearerValidationResponse(slice);

      } else {
        return AuthValidateInfo::generateFailed("Unauthorized");
      }
    } catch (const VPackException& ex) {
      return AuthValidateInfo::generateFailed("Failed to parse Auth service response. error: " + std::string(ex.what()));
    }

  } else if (res.status_code == 401) {
    return AuthValidateInfo::generateFailed("Unauthorized");
  } else if (res.status_code == 0) {
    return AuthValidateInfo::generateFailed("Failed to connect to Auth service");
  } else {
    std::stringstream error;
    error << "Authentication with auth service failed with code: " << res.status_code
          << ", reason: " << res.reason << ", response: " << res.text;
    return AuthValidateInfo::generateFailed(error.str());
  }
}


std::pair<bool, std::string> AuthValidator::authenticateWithAuthService() {
  AuthValidateInfo res = validateService(authConfig_.serviceAuthKey);
  if (res.valid) {
    serviceAuthTenants_ = res.authTenants;
    return {true, "OK"};
  }
  return {false, res.failureReason};
}

AuthValidateInfo AuthValidator::validateService(const std::string& serviceApiKey) {
  return validateApiKeywithAuthService(serviceApiKey);
}

AuthValidateInfo AuthValidator::validateApiKey(const std::string& key) {
  auto cacheRes = getApiKeyFromCache(key);
  if (cacheRes.first) { //cache hit (could be failure as well if expired key)
//    LOG_DEBUG << "UserAuthenticator::validateApiKey: Cache Hit. Key: " << key;
    return cacheRes.second;
  }
//  LOG_DEBUG << "UserAuthenticator::validateApiKey: Cache Miss. Key: " << key;
  //Cache miss
  auto res = validateApiKeywithAuthService(key);
  if (res.valid) {
    putApiKeyInCache(key, res);
  }
  return res;
}

AuthValidateInfo AuthValidator::validateApiKeywithAuthService(const std::string& key) {
  std::string url = authConfig_.authUrl + "/v1/apikeys/validate/" + key;
  cpr::Header headers;
  cpr::Response res = cpr::Get(cpr::Url{url},
                               headers,
                               cpr::Timeout{authConfig_.httpTimeoutSec * 1000},
                               authClientSslOpts_);
  if (res.status_code == 200) {
    if (res.text.empty()) {
      return AuthValidateInfo::generateFailed("Empty response received from Auth service");
    }
    try {
      VPackParser jsonParser;
      jsonParser.parse(res.text);
      auto slice = jsonParser.builder().slice();
      if (!slice.isObject()) {
        return AuthValidateInfo::generateFailed("Malformed response received from Auth service. Expecting a JSON Object");
      }
      return parseApiKeyValidationResponse(slice);
    } catch (const VPackException& ex) {
      return AuthValidateInfo::generateFailed("Failed to parse Auth service response. error: " + std::string(ex.what()));
    }
  } else if (res.status_code == 401) {
    return AuthValidateInfo::generateFailed("Unauthorized");
  } else if (res.status_code == 0) {
    return AuthValidateInfo::generateFailed("Failed to connect to Auth service");
  } else {
    std::stringstream error;
    error << "Validate Api Key with AuthService failed with code: " << res.status_code
          << ", reason: " << res.reason << ", response: " << res.text;
    return AuthValidateInfo::generateFailed(error.str());
  }
}

AuthValidateInfo AuthValidator::parseApiKeyValidationResponse(VPackSlice resData) {
  AuthValidateInfo validationRes;
  try {
    auto resultObj = resData.get("SuccessApikey");
    if (!resultObj.isObject()) {
      //This tag is not there means it is unauthorized!
      return AuthValidateInfo::generateFailed("Unauthorized");
    }
    auto validSlice = resultObj.get("valid");
    if (!validSlice.isBool()) {
      return AuthValidateInfo::generateFailed("Parsing failed: 'valid' field is not found or not a boolean");
    }
    if (!validSlice.getBool()) {
      return AuthValidateInfo::generateFailed("Key is not valid");
    }
    auto roleSlice = resultObj.get("role");
    if (!roleSlice.isUInt() &&  !roleSlice.isSmallInt()) {
      return AuthValidateInfo::generateFailed("Parsing failed: 'role' field is not found or not an unsigned int");
    }
    validationRes.role = roleSlice.getUIntUnchecked();

    auto keyIdSlice = resultObj.get("keyid");
    if (!keyIdSlice.isString()) {
      return AuthValidateInfo::generateFailed("Parsing failed: 'keyid' field is not found or not a string");
    }
    validationRes.id = keyIdSlice.copyString();

    auto tenantSlice = resultObj.get("tenant");
    if (!tenantSlice.isString()) {
      return AuthValidateInfo::generateFailed("Parsing failed: 'tenant' field is not found or not a string");
    }
    validationRes.tenant = tenantSlice.copyString();

    auto expiresAtSlice = resultObj.get("expires_at");
    if (!expiresAtSlice.isUInt() &&  !expiresAtSlice.isSmallInt()) {
      return AuthValidateInfo::generateFailed("Parsing failed: 'expires_at' field is not found or not an unsigned int");
    }
    validationRes.expiresAt = expiresAtSlice.getUIntUnchecked();

    if (resultObj.hasKey("auth_tenants")) {
      auto authTenantsSlice = resultObj.get("auth_tenants");
      if (!authTenantsSlice.isArray()) {
        return AuthValidateInfo::generateFailed("Parsing failed: 'auth_tenants' field is not found or not an array");
      }

      extractAuthTenants(validationRes.tenant, authTenantsSlice, validationRes.authTenants);
    }

    if (resultObj.hasKey("auth_os")) {
      auto authOsSlice = resultObj.get("auth_os");
      if (!authOsSlice.isArray()) {
        return AuthValidateInfo::generateFailed("Parsing failed: 'auth_os' field is not found or not an array");
      }
      extractAuthOs(validationRes.tenant, authOsSlice, validationRes.authOs);
    }

    validationRes.valid = true;
    return validationRes;

  } catch (const VPackException& ex) {
    return AuthValidateInfo::generateFailed("Parsing failed: Exception caught while parsing. error: " + std::string(ex.what()));
  }
}


AuthValidateInfo AuthValidator::validateBearer(const std::string& token) {
  std::string url = authConfig_.authUrl + "/v1/bearer/validate/" + token;
  cpr::Header headers;
  cpr::Response res = cpr::Get(cpr::Url{url},
                               headers,
                               cpr::Timeout{authConfig_.httpTimeoutSec * 1000},
                               authClientSslOpts_);
  if (res.status_code == 200) {
    if (res.text.empty()) {
      return AuthValidateInfo::generateFailed("Empty response received from Auth service");
    }
    try {
      VPackParser jsonParser;
      jsonParser.parse(res.text);
      auto slice = jsonParser.builder().slice();
      if (!slice.isObject()) {
        return AuthValidateInfo::generateFailed("Malformed response received from Auth service. Expecting a JSON Object");
      }
      return parseBearerValidationResponse(slice);
    } catch (const VPackException& ex) {
      return AuthValidateInfo::generateFailed("Failed to parse Auth service response. error: " + std::string(ex.what()));
    }

  } else if (res.status_code == 401) {
    return AuthValidateInfo::generateFailed("Unauthorized");
  } else if (res.status_code == 0) {
    return AuthValidateInfo::generateFailed("Failed to connect to Auth service");
  } else {
    std::stringstream error;
    error << "Authentication with auth service failed with code: " << res.status_code
          << ", reason: " << res.reason << ", response: " << res.text;
    return AuthValidateInfo::generateFailed(error.str());
  }
}

AuthValidateInfo AuthValidator::parseBearerValidationResponse(VPackSlice resData) {
  AuthValidateInfo validationRes;
  try {
    auto resultObj = resData.get("SuccessBearer");
    if (!resultObj.isObject()) {
      //This tag is not there means it is unauthorized!
      return AuthValidateInfo::generateFailed("Unauthorized");
    }
    auto validSlice = resultObj.get("valid");
    if (!validSlice.isBool()) {
      return AuthValidateInfo::generateFailed("Parsing failed: 'valid' field is not found or not a boolean");
    }
    if (!validSlice.getBool()) {
      return AuthValidateInfo::generateFailed("token is not valid");
    }
    auto roleSlice = resultObj.get("role");
    if (!roleSlice.isUInt() &&  !roleSlice.isSmallInt()) {
      return AuthValidateInfo::generateFailed("Parsing failed: 'role' field is not found or not an unsigned int");
    }
    validationRes.role = roleSlice.getUIntUnchecked();

    auto tenantSlice = resultObj.get("tenant");
    if (!tenantSlice.isString()) {
      return AuthValidateInfo::generateFailed("Parsing failed: 'tenant' field is not found or not a string");
    }
    validationRes.tenant = tenantSlice.copyString();

    auto expiresAtSlice = resultObj.get("expires_at");
    if (!expiresAtSlice.isUInt() &&  !expiresAtSlice.isSmallInt()) {
      return AuthValidateInfo::generateFailed("Parsing failed: 'expires_at' field is not found or not an unsigned int");
    }
    validationRes.expiresAt = expiresAtSlice.getUIntUnchecked();

    if (resultObj.hasKey("auth_tenants")) {
      auto authTenants = resultObj.get("auth_tenants");
      if (authTenants.isObject()) {
        return AuthValidateInfo::generateFailed("Parsing failed: 'auth_tenants' field is not found or not an object");
      }
      if (authTenants.hasKey(authConfig_.serviceId)) {
        auto authTenantForSvc = authTenants.get(authConfig_.serviceId);
        if (!authTenantForSvc.isArray()) {
          return AuthValidateInfo::generateFailed("Parsing failed: field for this service in 'auth_tenants' is not an array");
        }
        extractAuthTenants(validationRes.tenant, authTenantForSvc, validationRes.authTenants);
      }
    }

    if (resultObj.hasKey("auth_os")) {
      auto authOs = resultObj.get("auth_os");
      if (!authOs.isObject()) {
        return AuthValidateInfo::generateFailed("Parsing failed: 'auth_os' field is not found or not an object");
      }
      if (authOs.hasKey(authConfig_.serviceId)) {
        auto authOsForSvc = authOs.get(authConfig_.serviceId);
        if (!authOsForSvc.isArray()) {
          return AuthValidateInfo::generateFailed("Parsing failed: field for this service in 'auth_os' is not an array");
        }
        extractAuthOs(validationRes.tenant, authOsForSvc, validationRes.authOs);
      }
    }
    validationRes.valid = true;
    return validationRes;

  } catch (const VPackException& ex) {
    return AuthValidateInfo::generateFailed("Parsing failed: Exception caught while parsing. error: " + std::string(ex.what()));
  }
}

bool AuthValidator::extractAuthTenants(const std::string& tenantKey, VPackSlice input, std::list<GdnAttributes>& authTenants) {
  bool res = true;
  try {
    for (auto const& tenantSlice : VPackArrayIterator(input)) {
      if (!tenantSlice.isObject()) {
        std::cerr << "WARN: AuthValidator:extractAuthTenants: Tenant Key : " << tenantKey << ", One of the 'auth_tenants' elements is not an object";
        res = false;
        continue;
      }

      GdnAttributes gdnAttr;

      auto gdnTenantSlice = tenantSlice.get("gdn_tenant");
      if (!gdnTenantSlice.isString()) {
        std::cerr << "WARN: AuthValidator:extractAuthTenants: Tenant Key : " << tenantKey << ", 'gdn_tenant' field is not found or not a string in one of the auth_tenants";
        res = false;
        continue;
      }
      gdnAttr.gdnTenant = gdnTenantSlice.copyString();

      auto gdnKeySlice = tenantSlice.get("gdn_key");
      if (!gdnKeySlice.isString()) {
        std::cerr << "WARN: AuthValidator:extractAuthTenants: Tenant Key : " << tenantKey << ", 'gdn_key' field is not found or not a string in one of the auth_tenants";
        res = false;
        continue;
      }
      gdnAttr.gdnKey = gdnKeySlice.copyString();

      auto gdnUrlSlice = tenantSlice.get("gdn_url");
      if (!gdnUrlSlice.isString()) {
        std::cerr << "WARN: AuthValidator:extractAuthTenants: Tenant Key : " << tenantKey << ", 'gdn_url' field is not found or not a string in one of the auth_tenants";
        res = false;
        continue;
      }
      gdnAttr.gdnUrl = gdnUrlSlice.copyString();

      auto gdnStreamUrlSlice = tenantSlice.get("gdn_stream_url");
      if (!gdnStreamUrlSlice.isString()) {
        std::cerr << "WARN: AuthValidator:extractAuthTenants: Tenant Key : " << tenantKey << ", 'gdn_stream_url' field is not found or not a string in one of the auth_tenants";
        res = false;
        continue;
      }
      gdnAttr.gdnStreamUrl = gdnStreamUrlSlice.copyString();

      auto gdnFabricSlice = tenantSlice.get("gdn_fabric");
      if (!gdnFabricSlice.isString()) {
        std::cerr << "WARN: AuthValidator:extractAuthTenants: Tenant Key : " << tenantKey << ", 'gdn_fabric' field is not found or not a string in one of the auth_tenants";
        res = false;
        continue;
      }
      gdnAttr.gdnFabric = gdnFabricSlice.copyString();

      // Add the parsed GdnAttributes to the authTenants list
      authTenants.push_back(std::move(gdnAttr));
    }
  } catch (const VPackException& ex) {
    std::cerr << "WARN: AuthValidator:extractAuthTenants: Tenant Key : " << tenantKey << ", Failed to parse 'auth_tenants'. error: " + std::string(ex.what());
    res = false;
  }
  return res;
}

bool AuthValidator::extractAuthOs(const std::string& tenantKey, VPackSlice input, std::list<OsAttributes>& authOs) {
  bool res = true;
  try {
    for (auto const& osSlice : VPackArrayIterator(input)) {
      if (!osSlice.isObject()) {
        std::cerr << "WARN: AuthValidator:extractAuthOs: Tenant Key : " << tenantKey << ", One of the 'auth_os' elements is not an object";
        res = false;
        continue;
      }
      OsAttributes osAttr;

      auto osUrlSlice = osSlice.get("os_url");
      if (!osUrlSlice.isString()) {
        std::cerr << "WARN: AuthValidator:extractAuthOs: Tenant Key : " << tenantKey << ", 'os_url' field is not found or not a string in one of the auth_os";
        res = false;
        continue;
      }
      osAttr.osUrl = osUrlSlice.copyString();

      auto osTagSlice = osSlice.get("os_tag");
      if (!osTagSlice.isString()) {
        std::cerr << "WARN: AuthValidator:extractAuthOs: Tenant Key : " << tenantKey << ", 'os_tag' field is not found or not a string in one of the auth_os";
        res = false;
        continue;
      }
      osAttr.osTag = osTagSlice.copyString();

      auto allowedBuckSlice = osSlice.get("os_allowed_buckets");
      if (!allowedBuckSlice.isArray()) {
        std::cerr << "WARN: AuthValidator:extractAuthOs: Tenant Key : " << tenantKey << ", 'os_allowed_buckets' field is not found or not an Array in one of the auth_os";
        res = false;
        continue;
      }
      for (auto const& buckSlice : VPackArrayIterator(allowedBuckSlice)) {
        if (!buckSlice.isString()) {
          std::cerr << "WARN: AuthValidator:extractAuthOs: Tenant Key : " << tenantKey << ", An element in 'os_allowed_buckets' is not a string";
          res = false;
          continue;
        }
        osAttr.allowedBuckets.emplace(std::move(buckSlice.copyString()));
      }
      // Add the parsed OsAttributes to the authOS list
      authOs.push_back(std::move(osAttr));
    }
  } catch (const VPackException& ex) {
    std::cerr << "WARN: AuthValidator:extractAuthOs: Tenant Key : " << tenantKey << ", Failed to parse 'auth_os'. error: " + std::string(ex.what());
    res = false;
  }
  return res;
}

bool AuthValidator::extractServices(const std::string& tenantKey, VPackSlice input, std::set<std::string>& services) {
  bool res = true;
  try {
    for (auto const& serviceSlice : VPackArrayIterator(input)) {
      if (!serviceSlice.isString()) {
        std::cerr << "WARN: AuthValidator:extractServices: Tenant Key : " << tenantKey << ", One of the 'services' elements is not a string";
        res = false;
        continue;
      }
      services.emplace(serviceSlice.copyString());
    }
  } catch (const VPackException& ex) {
    std::cerr << "WARN: AuthValidator:extractServices: Tenant Key : " << tenantKey << ", Failed to parse 'auth_os'. error: " + std::string(ex.what());
    res = false;
  }
  return res;
}


std::pair<bool, std::string> AuthValidator::subscribeToStreams() {
  if (serviceAuthTenants_.empty()) {
    return {false, "Failed to subscribe to streams. Service Auth Tenants empty"};
  }
  // Configure the Pulsar client
  pulsar::ClientConfiguration clientConfig;
  clientConfig.setAuth(pulsar::AuthToken::createWithToken(serviceAuthTenants_.front().gdnKey));
  clientConfig.setTlsAllowInsecureConnection(true);
  pulsarClientPtr_ = std::make_shared<pulsar::Client>(pulsar::Client(serviceAuthTenants_.front().gdnStreamUrl, clientConfig));

  // Map of topic names to callback methods
  std::map<std::string, void (AuthValidator::*)(const std::string&)> topicCallbacks = {
    {"auth_tenants", &AuthValidator::onTenantChange},
    {"auth_users", &AuthValidator::onUserChange},
    {"auth_apikeys", &AuthValidator::onApiKeyChange}
  };

  auto topicPrefix = "persistent://" + serviceAuthTenants_.front().gdnTenant + "/c8local." + serviceAuthTenants_.front().gdnFabric + "/";

  try {
    for (const auto& [topic, callback] : topicCallbacks) {
      std::string fullTopicName = topicPrefix + topic;

      pulsar::ReaderConfiguration readerConfig;
      readerConfig.setReaderListener([this, callback](pulsar::Reader reader, const pulsar::Message& msg) {
        (this->*callback)(std::string((char*)msg.getData(), msg.getLength()));  // Call the appropriate callback
      });

      pulsar::Reader reader;
      auto result = pulsarClientPtr_->createReader(fullTopicName, pulsar::MessageId::latest(), readerConfig, reader);
      if (result != pulsar::ResultOk) {
        return {false, "Failed to subscribe to streams. Failed to create reader for topic: " + fullTopicName};
      }
    }
    return {true, "OK"};

  } catch (const std::exception& ex) {
    return {false, "Exception occurred while subscribing to streams: " + std::string(ex.what())};
  }
}

void AuthValidator::onTenantChange(const std::string& msg) {

  //LOG_DEBUG << "AuthClient::onTenantChange: message: " << msg;
  bool deleted = false;
  try {
    VPackParser jsonParser;
    jsonParser.parse(msg);
    auto tenantSlice = jsonParser.builder().slice();
    if (!tenantSlice.isObject()) {
      std::cerr << "WARN: AuthValidator:onTenantChange: Failed to parse a message received from tenant stream topic. Received message is not a JSON object. message: " << msg;
      return;
    }
    if(tenantSlice.get("_delete").isBool() && tenantSlice.get("_delete").getBool()) {
      deleted = true;
    }
    auto keySlice = tenantSlice.get("_key");
    if (!keySlice.isString()) {
      std::cerr << "WARN: AuthValidator:onTenantChange: '_key' field not found or not a string in a message received from tenant stream topic. message: " << msg;
      return;
    }
    AuthTenant tenant;
    tenant.tenant = keySlice.copyString();

    if (tenantSlice.hasKey("auth_os")) {
      auto servicesSlice = tenantSlice.get("services");
      if (!servicesSlice.isArray()) {
          std::cerr << "WARN: AuthValidator:onTenantChange: 'services' field is not an array in a message received from tenant stream topic. message: " << msg;
          return;
      }

      if (!extractServices(tenant.tenant, servicesSlice, tenant.services)) {
        std::cerr << "WARN: AuthValidator: Failed to process services in a message received from tenant stream topic. message: " << msg;
        return;
      }
      //Even this service is not present in the services list we call the callback.
      //Why? becuase if the service is removed from the services list, we sould still call the callback
      //And this gives this service a chance to do required things with this tenant if this service is removed from the tenant,
      //such as remove the tenant from this service's internal data structures.
    }

    if (tenantSlice.hasKey("auth_tenants")) {
      auto authTenantsSlice = tenantSlice.get("auth_tenants");
      if (!authTenantsSlice.isArray()) {
        std::cerr << "WARN: AuthValidator:onTenantChange: 'auth_tenants' field not found or not an array in a message received from tenant stream topic. message: " << msg;
        return;
      }

      if (!extractAuthTenants(tenant.tenant, authTenantsSlice, tenant.authTenants)) {
        std::cerr << "WARN: AuthValidator:onTenantChange: Failed to process auth_tenants in a message received from tenant stream topic. message: " << msg;
        return;
      }
    }

    if (tenantSlice.hasKey("auth_os")) {
      auto authOsSlice = tenantSlice.get("auth_os");
      if (!authOsSlice.isArray()) {
        std::cerr << "WARN: AuthValidator:onTenantChange: 'auth_os' field not found or not an array in a message received from tenant stream topic. message: " << msg;
        return;
      }

      if (!extractAuthOs(tenant.tenant, authOsSlice, tenant.authOs)) {
        std::cerr << "WARN: AuthValidator:onTenantChange: Failed to process auth_os in a message received from tenant stream topic. message: " << msg;
        return;
      }
    }

    if (tenantChangeCallback_) {
        tenantChangeCallback_(tenant, deleted);
    }

  } catch (const VPackException& ex) {
    std::cerr << "WARN: AuthValidator:onTenantChange: Failed to parse a message received from apikey stream topic. Error: "
              << ex.what() << ", message: " << msg;
  }

}

void AuthValidator::onUserChange(const std::string& msg) {
  //Not implemented yet..

}

void AuthValidator::onApiKeyChange(const std::string& msg) {
  //LOG_DEBUG << "AuthClient::onApiKeyChange: message: " << msg;
  try {
    VPackParser jsonParser;
    jsonParser.parse(msg);
    auto slice = jsonParser.builder().slice();
    if (!slice.isObject()) {
      std::cerr << "WARN: AuthValidator:onApiKeyChange: Failed to parse a message received from apikey stream topic. Received message is not a JSON object. message: " << msg;
      return;
    }
    auto keySlice = slice.get("_key");
    if (!keySlice.isString()) {
      std::cerr << "WARN: AuthValidator:onApiKeyChange: '_key' field not found or not a string in a message received from APIKey stream topic. message: " << msg;
      return;
    }
    auto keyId = keySlice.copyString();
    removeApiKeyByKeyId(keyId);

  } catch (const VPackException& ex) {
    std::cerr << "WARN: AuthValidator:onApiKeyChange: Failed to parse a message received from apikey stream topic. Error: "
              << ex.what() << ", message: " << msg;
  }
}

std::pair<bool, AuthValidateInfo> AuthValidator::getApiKeyFromCache(const std::string& key) {

  std::shared_lock readLock(apiKeyCacheLock_);
  auto itr = apiKeyCache_.find(key);
  if (itr != apiKeyCache_.end()) { // Cache hit

    auto currentTime = getCurrentEpochTimeInSec();
    if (currentTime > itr->second.expiresAt) {
      return {true, AuthValidateInfo::generateFailed("API Key expired")};
    }
    return {true, itr->second};
  } else {
    return {false, {}};
  }
}

void AuthValidator::putApiKeyInCache(const std::string& key, const AuthValidateInfo& info) {
  std::unique_lock writeLock(apiKeyCacheLock_);
  apiKeyCache_[key] = info;
  apiKeyIdToKeyMap_[info.id] = key;
}

bool AuthValidator::removeApiKeyByKeyId(const std::string& keyId) {

  std::unique_lock writeLock(apiKeyCacheLock_);
  auto itr = apiKeyIdToKeyMap_.find(keyId);

  if (itr != apiKeyIdToKeyMap_.end()) {
   if (apiKeyCache_.erase(itr->second) > 0 ) {
     apiKeyIdToKeyMap_.erase(itr);
     return true;
   }
  }
  return false;
}


uint64_t AuthValidator::getCurrentEpochTimeInSec() {
    return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}
