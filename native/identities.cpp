// SPDX-License-Identifier: GPL-3.0-or-later
#include "identities.h"
#include <algorithm>
#include <arpa/inet.h>
#include <chrono>
#include <condition_variable>
#include <fcntl.h>
#include <fstream>
#include <gio/gio.h>
#include <memory>
#include <mutex>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>
#include <set>
#include <sys/file.h>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>
namespace identities {
namespace {
template <class T, void (*Free)(T *)>
using Ossl = std::unique_ptr<T, decltype(Free)>;
struct Fd {
  int value = -1;
  explicit Fd(int n) : value(n) {}
  ~Fd() {
    if (value >= 0)
      close(value);
  }
  operator int() const { return value; }
};
void require(bool value, const char *message) {
  if (!value)
    throw std::runtime_error(message);
}
std::string read(const fs::path &path, bool secret = false,
                 size_t limit = 65536, bool identityCertificate = false) {
  Fd file(open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
  struct stat st{};
  require(file >= 0 && fstat(file, &st) == 0 && S_ISREG(st.st_mode),
          "Cannot open a regular identity file");
  require(st.st_size >= 0 && size_t(st.st_size) <= limit,
          "Identity file exceeds its size limit");
  require(!secret || (st.st_uid == geteuid() && !(st.st_mode & 0077)),
          "Private files must be owned by you with owner-only permissions");
  require(
      !identityCertificate || (st.st_uid == geteuid() && !(st.st_mode & 0022)),
      "Shared certificates must be owned by you and not writable by others");
  std::string out;
  char buffer[4096];
  ssize_t count;
  while ((count = ::read(file, buffer, sizeof buffer)) > 0) {
    out.append(buffer, size_t(count));
    require(out.size() <= limit, "Identity file exceeds its size limit");
  }
  require(count == 0, "Cannot read identity file");
  return out;
}
void writeNew(const fs::path &path, const std::string &bytes) {
  Fd file(open(path.c_str(),
               O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600));
  require(file >= 0,
          "Cannot create file; choose a destination that does not exist");
  try {
    size_t offset = 0;
    while (offset < bytes.size()) {
      auto count = ::write(file, bytes.data() + offset, bytes.size() - offset);
      if (count < 0 && errno == EINTR)
        continue;
      require(count > 0, "Cannot write identity file");
      offset += size_t(count);
    }
    require(fsync(file) == 0, "Cannot flush identity file");
  } catch (...) {
    unlink(path.c_str());
    throw;
  }
}
void privateRoot(const fs::path &root) {
  fs::create_directories(root);
  struct stat st{};
  require(lstat(root.c_str(), &st) == 0 && S_ISDIR(st.st_mode) &&
              st.st_uid == geteuid(),
          "Identity directory must be owned by you");
  if (st.st_mode & 0077)
    require(chmod(root.c_str(), 0700) == 0,
            "Cannot protect identity directory");
}
struct Lock {
  Fd fd;
  explicit Lock(const fs::path &root)
      : fd((privateRoot(root),
            open((root / "index.lock").c_str(),
                 O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK,
                 0600))) {
    struct stat st{};
    require(fd >= 0 && fstat(fd, &st) == 0 && S_ISREG(st.st_mode) &&
                st.st_uid == geteuid() && !(st.st_mode & 0077),
            "Cannot lock the private identity catalog");
    auto until = std::chrono::steady_clock::now() + std::chrono::seconds(30);
    while (flock(fd, LOCK_EX | LOCK_NB) != 0) {
      require((errno == EWOULDBLOCK || errno == EINTR) &&
                  std::chrono::steady_clock::now() < until,
              "Identity catalog is busy; try again");
      std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
  }
};
void save(const fs::path &path, const Json &document,
          bool *published = nullptr) {
  auto bytes = document.dump(2) + "\n";
  require(bytes.size() <= 1024 * 1024, "Identity catalog exceeds 1 MiB");
  std::string pattern = (path.parent_path() / ".index-XXXXXX").string();
  std::vector<char> temporary(pattern.begin(), pattern.end());
  temporary.push_back(0);
  Fd file(mkostemp(temporary.data(), O_CLOEXEC));
  require(file >= 0, "Cannot stage identity catalog");
  try {
    size_t offset = 0;
    while (offset < bytes.size()) {
      auto count = ::write(file, bytes.data() + offset, bytes.size() - offset);
      require(count > 0, "Cannot write identity catalog");
      offset += size_t(count);
    }
    require(fsync(file) == 0, "Cannot flush identity catalog");
    require(rename(temporary.data(), path.c_str()) == 0,
            "Cannot replace identity catalog");
    if (published)
      *published = true;
    Fd directory(
        open(path.parent_path().c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    require(directory >= 0 && fsync(directory) == 0,
            "Cannot sync identity catalog directory");
  } catch (...) {
    unlink(temporary.data());
    throw;
  }
}
Ossl<X509, X509_free> certificate(const std::string &bytes) {
  Ossl<BIO, BIO_free_all> bio(BIO_new_mem_buf(bytes.data(), int(bytes.size())),
                              BIO_free_all);
  Ossl<X509, X509_free> cert(PEM_read_bio_X509(
                                 bio.get(), nullptr,
                                 [](char *, int, int, void *) { return 0; },
                                 nullptr),
                             X509_free);
  require(bool(cert), "Invalid PEM certificate");
  return cert;
}
std::string bioText(BIO *bio) {
  char *data = nullptr;
  long count = BIO_get_mem_data(bio, &data);
  return count > 0 ? std::string(data, size_t(count)) : "";
}
std::string fingerprint(X509 *cert) {
  unsigned char digest[EVP_MAX_MD_SIZE];
  unsigned int size = 0;
  require(X509_digest(cert, EVP_sha256(), digest, &size) == 1,
          "Cannot fingerprint certificate");
  std::string result;
  const char *hex = "0123456789abcdef";
  for (unsigned i = 0; i < size; ++i) {
    result += hex[digest[i] >> 4];
    result += hex[digest[i] & 15];
  }
  return result;
}
bool validText(const std::string &value) {
  if (!g_utf8_validate(value.data(), gssize(value.size()), nullptr))
    return false;
  for (auto at = value.data(); at < value.data() + value.size();
       at = g_utf8_next_char(at))
    if (g_unichar_iscntrl(g_utf8_get_char(at)))
      return false;
  return true;
}
void validName(const std::string &name) {
  bool visible = false;
  if (validText(name))
    for (auto at = name.data(); at < name.data() + name.size();
         at = g_utf8_next_char(at))
      visible |= !g_unichar_isspace(g_utf8_get_char(at));
  require(visible && name.size() <= 256,
          "Enter a UTF-8 identity name of 1 to 256 bytes without control "
          "characters");
}

} // namespace
fs::path catalogPath() {
  const char *data = getenv("XDG_DATA_HOME"), *home = getenv("HOME");
  fs::path base;
  if (data && fs::path(data).is_absolute())
    base = data;
  else {
    require(home && fs::path(home).is_absolute(),
            "Cannot find an absolute identity data directory");
    base = fs::path(home) / ".local/share";
  }
  return base / "de-xr/identities/index.json";
}

static Json inspectPem(const std::string &pem, const std::string &key = {}) {
  require(pem.size() <= 65536 && key.size() <= 65536,
          "Identity exceeds 64 KiB");
  auto cert = certificate(pem);
  std::string address;
  int index = X509_NAME_get_index_by_NID(X509_get_subject_name(cert.get()),
                                         NID_userId, -1);
  Ossl<GENERAL_NAMES, GENERAL_NAMES_free> names(
      static_cast<GENERAL_NAMES *>(
          X509_get_ext_d2i(cert.get(), NID_subject_alt_name, nullptr, nullptr)),
      GENERAL_NAMES_free);
  if (index >= 0 && names) {
    auto value = X509_NAME_ENTRY_get_data(
        X509_NAME_get_entry(X509_get_subject_name(cert.get()), index));
    unsigned char *uid = nullptr;
    int length = ASN1_STRING_to_UTF8(&uid, value);
    std::string mailbox =
        length > 0 ? std::string(reinterpret_cast<char *>(uid), size_t(length))
                   : "";
    OPENSSL_free(uid);
    for (int i = 0; i < sk_GENERAL_NAME_num(names.get()); ++i) {
      auto name = sk_GENERAL_NAME_value(names.get(), i);
      if (name->type == GEN_DNS) {
        auto value = name->d.dNSName;
        std::string dns(
            reinterpret_cast<const char *>(ASN1_STRING_get0_data(value)),
            size_t(ASN1_STRING_length(value)));
        if (dns.find('\0') == std::string::npos)
          address = mailbox + "@" + dns;
        break;
      }
    }
  }
  if (!key.empty()) {
    Ossl<BIO, BIO_free_all> bio(
        BIO_new_mem_buf(key.data(), int(key.size())), BIO_free_all);
    Ossl<EVP_PKEY, EVP_PKEY_free> privateKey(
        PEM_read_bio_PrivateKey(
            bio.get(), nullptr, [](char *, int, int, void *) { return 0; },
            nullptr),
        EVP_PKEY_free);
    require(privateKey &&
                X509_check_private_key(cert.get(), privateKey.get()) == 1,
            "Certificate and unencrypted private key do not match");
  }
  Ossl<BIO, BIO_free_all> details(BIO_new(BIO_s_mem()), BIO_free_all);
  X509_print_ex(details.get(), cert.get(), 0,
                X509_FLAG_NO_EXTENSIONS | X509_FLAG_NO_PUBKEY |
                    X509_FLAG_NO_SIGDUMP);
  return {
      {"id", fingerprint(cert.get())},
      {"address", address},
      {"details", bioText(details.get())},
      {"valid", X509_cmp_current_time(X509_get0_notBefore(cert.get())) < 0 &&
                    X509_cmp_current_time(X509_get0_notAfter(cert.get())) > 0}};
}
Json inspect(const fs::path &path, const fs::path &key) {
  return inspectPem(read(path, false, 65536, !key.empty()),
                    key.empty() ? std::string() : read(key, true));
}

fs::path penguinStorePath() {
  return catalogPath().parent_path().parent_path().parent_path() /
         "penguin-mail/misfin/state.json";
}
static Json penguinRecords(const fs::path &store) {
  require(store.is_absolute(), "Choose an absolute Penguin Mail store path");
  struct stat st{};
  if (lstat(store.c_str(), &st) && errno == ENOENT)
    return Json::array();
  auto bytes = read(store, true, 8 * 1024 * 1024);
  try {
    auto document = Json::parse(bytes);
    const auto &entries = document.at("identities");
    require(entries.is_array() && entries.size() <= 16,
            "Invalid Penguin Mail identity list");
    std::set<std::string> ids;
    for (const auto &entry : entries) {
      auto id = entry.at("id").get<std::string>();
      require(id.size() == 64 &&
                  id.find_first_not_of("0123456789abcdef") == std::string::npos &&
                  ids.insert(id).second && entry.at("certificate").is_string() &&
                  entry.at("key").is_string() &&
                  entry.at("certificate").get_ref<const std::string &>().size() <= 65536 &&
                  entry.at("key").get_ref<const std::string &>().size() <= 65536,
              "Invalid Penguin Mail identity record");
    }
    return entries;
  } catch (const Json::exception &) {
    // JSON diagnostics can quote input from a store containing private keys.
    throw std::runtime_error("Invalid Penguin Mail identity store");
  }
}
Json penguinIdentities(const fs::path &store) {
  Json available = Json::array();
  for (const auto &entry : penguinRecords(store)) {
    try {
      auto checked = inspectPem(entry.at("certificate"));
      auto address = checked.at("address").get<std::string>();
      if (checked.at("id") != entry.at("id") || !checked.at("valid").get<bool>() ||
          address.empty() || address.size() > 320 || !validText(address))
        continue;
      available.push_back({{"id", entry.at("id")}, {"address", address}});
    } catch (const std::exception &) {
      // Listing needs public metadata only; unusable certificates are omitted.
    }
  }
  return available;
}
Json importPenguinIdentity(const fs::path &catalog, const fs::path &store,
                           const std::string &id, const std::string &name) {
  validName(name);
  require(catalog.is_absolute(), "Choose an absolute shared catalog path");
  auto entries = penguinRecords(store);
  auto selected = std::find_if(entries.begin(), entries.end(),
                               [&](const Json &entry) { return entry.at("id") == id; });
  require(selected != entries.end(), "Choose an available Penguin Mail identity");
  const auto &pem = selected->at("certificate").get_ref<const std::string &>();
  const auto &key = selected->at("key").get_ref<const std::string &>();
  require(!key.empty(), "The selected Penguin Mail identity has no private key");
  auto checked = inspectPem(pem, key);
  auto address = checked.at("address").get<std::string>();
  require(checked.at("id") == id && checked.at("valid").get<bool>() &&
              !address.empty() && address.size() <= 320 && validText(address),
          "The selected Penguin Mail identity is unavailable or has changed");
  Lock lock(catalog.parent_path());
  auto document = list(catalog);
  for (const auto &existing : document["identities"])
    if (existing.at("id") == id) {
      auto current = inspect(existing.at("certificate").get<std::string>(),
                             existing.at("key").get<std::string>());
      require(current.at("id") == id && current.at("valid").get<bool>(),
              "Repair or remove the existing shared identity reference first");
      return existing; // Keep any existing PEM paths and user-assigned name.
    }
  require(document["identities"].size() < 256,
          "At most 256 entries can be stored in one catalog");
  auto directory = catalog.parent_path() / id;
  bool created = mkdir(directory.c_str(), 0700) == 0;
  if (!created) {
    struct stat st{};
    require(errno == EEXIST && lstat(directory.c_str(), &st) == 0 &&
                S_ISDIR(st.st_mode) && st.st_uid == geteuid() && !(st.st_mode & 0077),
            "Cannot use a private shared identity directory");
  }
  auto certificatePath = directory / "certificate.pem", keyPath = directory / "key.pem";
  bool published = false;
  try {
    if (created) {
      writeNew(keyPath, key);
      writeNew(certificatePath, pem);
    } else {
      auto current = inspect(certificatePath, keyPath);
      require(current.at("id") == id && current.at("valid").get<bool>(),
              "An existing shared PEM pair does not match the selected identity");
    }
    Json record = {{"id", id}, {"name", name}, {"address", address},
                   {"certificate", certificatePath.string()}, {"key", keyPath.string()}};
    document["identities"].push_back(record);
    save(catalog, document, &published);
    return record;
  } catch (...) {
    if (created && !published) {
      unlink(keyPath.c_str()); unlink(certificatePath.c_str()); rmdir(directory.c_str());
    }
    throw;
  }
}
Json list(const fs::path &catalog, bool publicOnly) {
  auto path =
      publicOnly ? catalog.parent_path() / "certificates.json" : catalog;
  const char *collection = publicOnly ? "certificates" : "identities";
  struct stat st{};
  if (lstat(path.c_str(), &st) && errno == ENOENT)
    return {{"version", 1}, {collection, Json::array()}};
  auto document = Json::parse(read(path, true, 1024 * 1024));
  require(document.at("version") == 1 && document.at(collection).is_array() &&
              document.at(collection).size() <= 256,
          "Invalid identity or certificate catalog");
  std::set<std::string> ids;
  for (auto &entry : document.at(collection)) {
    auto id = entry.at("id").get<std::string>();
    validName(entry.at("name"));
    if (entry.contains("address")) {
      require(entry.at("address").is_string(), "Invalid catalog address");
      auto address = entry.at("address").get<std::string>();
      require(address.size() <= 320 && validText(address),
              "Invalid catalog address");
    }
    require(id.size() == 64 &&
                id.find_first_not_of("0123456789abcdef") == std::string::npos &&
                ids.insert(id).second &&
                fs::path(entry.at("certificate").get<std::string>())
                    .is_absolute() &&
                (publicOnly ||
                 fs::path(entry.at("key").get<std::string>()).is_absolute()),
            "Invalid identity or certificate catalog");
  }
  return document;
}
static Json adoptImpl(const fs::path &catalog, const std::string &name,
                      const fs::path &cert, const fs::path &key,
                      bool *published) {
  validName(name);
  bool publicOnly = key.empty();
  require(cert.is_absolute() && (publicOnly || key.is_absolute()),
          "Choose absolute certificate and key paths");
  auto checked = inspect(cert, key);
  require(checked.at("valid").get<bool>(),
          "Certificate is not currently valid");
  Lock lock(catalog.parent_path());
  auto document = list(catalog, publicOnly);
  const char *collection = publicOnly ? "certificates" : "identities";
  Json record = {
      {"id", checked.at("id")}, {"name", name}, {"certificate", cert.string()}};
  if (!publicOnly)
    record["key"] = key.string();
  auto address = checked.at("address").get<std::string>();
  if (!address.empty() && address.size() <= 320 && validText(address))
    record["address"] = address;
  bool replaced = false;
  for (auto &entry : document[collection])
    if (entry.at("id") == record.at("id")) {
      entry = record;
      replaced = true;
      break;
    }
  if (!replaced) {
    require(document[collection].size() < 256,
            "At most 256 entries can be stored in one catalog");
    document[collection].push_back(record);
  }
  save(publicOnly ? catalog.parent_path() / "certificates.json" : catalog,
       document, published);
  return record;
}
Json adopt(const fs::path &catalog, const std::string &name,
           const fs::path &certificate, const fs::path &key) {
  return adoptImpl(catalog, name, certificate, key, nullptr);
}
Json generate(const fs::path &catalog, const std::string &name,
              const std::string &address) {
  validName(name);
  require(g_utf8_strlen(name.data(), gssize(name.size())) <= 64,
          "Certificate names support at most 64 Unicode characters");
  require(validText(address),
          "Enter a UTF-8 mailbox@hostname address without control characters");
  auto split = address.find('@');
  require(split != std::string::npos && split > 0 && split <= 64 &&
              address.find('@', split + 1) == std::string::npos,
          "Enter a mailbox@hostname address");
  auto mailbox = address.substr(0, split), host = address.substr(split + 1);
  require(std::all_of(mailbox.begin(), mailbox.end(),
                      [](unsigned char c) {
                        return (c >= 'a' && c <= 'z') ||
                               (c >= 'A' && c <= 'Z') ||
                               (c >= '0' && c <= '9') ||
                               std::string("._+-").find(char(c)) !=
                                   std::string::npos;
                      }),
          "Invalid mailbox name");
  std::unique_ptr<gchar, decltype(&g_free)> ascii(
      g_hostname_to_ascii(host.c_str()), g_free);
  require(bool(ascii), "Invalid DNS hostname");
  host = ascii.get();
  in_addr ipv4{};
  require(inet_aton(host.c_str(), &ipv4) != 1,
          "Identity requires a DNS hostname");
  require(!host.empty() && host.size() <= 253 && host.front() != '.' &&
              host.back() != '.' && host.find("..") == std::string::npos,
          "Invalid DNS hostname");
  auto last = host.substr(host.find_last_of('.') == std::string::npos
                              ? 0
                              : host.find_last_of('.') + 1);
  bool numeric = std::all_of(last.begin(), last.end(), [](unsigned char c) {
    return c >= '0' && c <= '9';
  });
  bool hexadecimal =
      last.size() > 2 && last.substr(0, 2) == "0x" &&
      std::all_of(last.begin() + 2, last.end(),
                  [](unsigned char c) { return g_ascii_isxdigit(c); });
  require(!numeric && !hexadecimal,
          "Identity requires a DNS hostname rather than a numeric address");
  size_t start = 0;
  while (start < host.size()) {
    auto end = host.find('.', start);
    auto label =
        host.substr(start, end == std::string::npos ? end : end - start);
    require(!label.empty() && label.size() <= 63 && label.front() != '-' &&
                label.back() != '-' &&
                std::all_of(label.begin(), label.end(),
                            [](unsigned char c) {
                              return (c >= 'a' && c <= 'z') ||
                                     (c >= 'A' && c <= 'Z') ||
                                     (c >= '0' && c <= '9') || c == '-';
                            }),
            "Invalid DNS hostname");
    if (end == std::string::npos)
      break;
    start = end + 1;
  }
  std::transform(host.begin(), host.end(), host.begin(),
                 [](unsigned char c) { return char(std::tolower(c)); });
  Ossl<EVP_PKEY_CTX, EVP_PKEY_CTX_free> context(
      EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr), EVP_PKEY_CTX_free);
  require(context && EVP_PKEY_keygen_init(context.get()) > 0 &&
              EVP_PKEY_CTX_set_rsa_keygen_bits(context.get(), 2048) > 0,
          "Cannot initialize RSA identity generation");
  EVP_PKEY *raw = nullptr;
  require(EVP_PKEY_keygen(context.get(), &raw) > 0,
          "Cannot generate identity key");
  Ossl<EVP_PKEY, EVP_PKEY_free> key(raw, EVP_PKEY_free);
  Ossl<X509, X509_free> cert(X509_new(), X509_free);
  require(bool(cert), "Cannot create certificate");
  X509_set_version(cert.get(), 2);
  unsigned char serial[16];
  require(RAND_bytes(serial, sizeof serial) == 1,
          "Cannot generate certificate serial");
  serial[0] &= 0x7f;
  Ossl<BIGNUM, BN_free> number(BN_bin2bn(serial, sizeof serial, nullptr),
                               BN_free);
  Ossl<ASN1_INTEGER, ASN1_INTEGER_free> integer(
      BN_to_ASN1_INTEGER(number.get(), nullptr), ASN1_INTEGER_free);
  X509_set_serialNumber(cert.get(), integer.get());
  X509_gmtime_adj(X509_getm_notBefore(cert.get()), 0);
  X509_gmtime_adj(X509_getm_notAfter(cert.get()), 5L * 365 * 86400);
  X509_set_pubkey(cert.get(), key.get());
  auto subject = X509_get_subject_name(cert.get());
  require(X509_NAME_add_entry_by_NID(
              subject, NID_userId, MBSTRING_UTF8,
              reinterpret_cast<const unsigned char *>(mailbox.data()),
              int(mailbox.size()), -1, 0) == 1 &&
              X509_NAME_add_entry_by_NID(
                  subject, NID_commonName, MBSTRING_UTF8,
                  reinterpret_cast<const unsigned char *>(name.data()),
                  int(name.size()), -1, 0) == 1,
          "Cannot set identity name");
  X509_set_issuer_name(cert.get(), subject);
  for (auto extension : std::vector<std::pair<int, std::string>>{
           {NID_basic_constraints, "critical,CA:FALSE"},
           {NID_key_usage, "critical,digitalSignature"},
           {NID_ext_key_usage, "clientAuth"},
           {NID_subject_alt_name, "DNS:" + host}}) {
    Ossl<X509_EXTENSION, X509_EXTENSION_free> ext(
        X509V3_EXT_conf_nid(nullptr, nullptr, extension.first,
                            extension.second.c_str()),
        X509_EXTENSION_free);
    require(ext && X509_add_ext(cert.get(), ext.get(), -1) == 1,
            "Cannot set identity certificate extensions");
  }
  require(X509_sign(cert.get(), key.get(), EVP_sha256()) > 0,
          "Cannot sign identity certificate");
  Ossl<BIO, BIO_free_all> cb(BIO_new(BIO_s_mem()), BIO_free_all),
      kb(BIO_new(BIO_s_mem()), BIO_free_all);
  require(PEM_write_bio_X509(cb.get(), cert.get()) == 1 &&
              PEM_write_bio_PrivateKey(kb.get(), key.get(), nullptr, nullptr, 0,
                                       nullptr, nullptr) == 1,
          "Cannot encode identity");
  privateRoot(catalog.parent_path());
  auto id = fingerprint(cert.get());
  auto pairRoot = catalog.parent_path() / id;
  require(
      mkdir(pairRoot.c_str(), 0700) == 0,
      "The generated identity directory already exists or cannot be created");
  auto certPath = pairRoot / "certificate.pem", keyPath = pairRoot / "key.pem";
  bool published = false;
  try {
    writeNew(keyPath, bioText(kb.get()));
    writeNew(certPath, bioText(cb.get()));
    return adoptImpl(catalog, name, certPath, keyPath, &published);
  } catch (...) {
    if (!published) {
      unlink(keyPath.c_str());
      unlink(certPath.c_str());
      rmdir(pairRoot.c_str());
    }
    throw;
  }
}
void remove(const fs::path &catalog, const std::string &id, bool publicOnly) {
  Lock lock(catalog.parent_path());
  auto document = list(catalog, publicOnly);
  auto &entries = document[publicOnly ? "certificates" : "identities"];
  auto previous = entries.size();
  entries.erase(
      std::remove_if(entries.begin(), entries.end(),
                     [&](const Json &entry) { return entry.at("id") == id; }),
      entries.end());
  require(entries.size() != previous,
          "Selected identity is no longer available");
  save(publicOnly ? catalog.parent_path() / "certificates.json" : catalog,
       document);
}
void exportCertificate(const fs::path &catalog, const std::string &id,
                       const fs::path &destination, bool publicOnly) {
  auto document = list(catalog, publicOnly);
  for (auto &entry : document[publicOnly ? "certificates" : "identities"]) {
    if (entry.at("id") == id) {
      auto bytes = read(entry.at("certificate").get<std::string>(), false,
                        65536, !publicOnly);
      auto cert = certificate(bytes);
      require(fingerprint(cert.get()) == id, "Certificate fingerprint changed");
      Ossl<BIO, BIO_free_all> output(BIO_new(BIO_s_mem()), BIO_free_all);
      PEM_write_bio_X509(output.get(), cert.get());
      writeNew(destination, bioText(output.get()));
      return;
    }
  }
  throw std::runtime_error("Select an identity first");
}
void exportPemIdentity(const fs::path &catalog, const std::string &id,
                       const fs::path &destination) {
  auto document = list(catalog);
  for (const auto &entry : document["identities"])
    if (entry.at("id") == id) {
      auto certPath = entry.at("certificate").get<std::string>(),
           keyPath = entry.at("key").get<std::string>();
      auto checked = inspect(certPath, keyPath);
      require(checked.at("id") == id, "Certificate fingerprint changed");
      auto cert = certificate(read(certPath, false, 65536, true));
      require(fingerprint(cert.get()) == id, "Certificate fingerprint changed");
      auto bytes = read(keyPath, true);
      Ossl<BIO, BIO_free_all> input(
          BIO_new_mem_buf(bytes.data(), int(bytes.size())), BIO_free_all);
      Ossl<EVP_PKEY, EVP_PKEY_free> key(
          PEM_read_bio_PrivateKey(
              input.get(), nullptr, [](char *, int, int, void *) { return 0; },
              nullptr),
          EVP_PKEY_free);
      require(key && X509_check_private_key(cert.get(), key.get()) == 1,
              "Certificate and private key do not match");
      Ossl<BIO, BIO_free_all> output(BIO_new(BIO_s_mem()), BIO_free_all);
      require(PEM_write_bio_X509(output.get(), cert.get()) == 1 &&
                  PEM_write_bio_PrivateKey(output.get(), key.get(), nullptr,
                                           nullptr, 0, nullptr, nullptr) == 1,
              "Cannot encode identity backup");
      writeNew(destination, bioText(output.get()));
      return;
    }
  throw std::runtime_error("Select an identity first");
}
std::string gpg(const std::string &program,
                const std::vector<std::string> &args, bool mayAsk) {
  require(program == "gpg" || program == "gpgsm", "Unsupported key engine");
  std::vector<std::string> command = {program, "--batch", "--no-tty",
                                      "--pinentry-mode",
                                      mayAsk ? "ask" : "error"};
  command.insert(command.end(), args.begin(), args.end());
  std::vector<const gchar *> argv;
  for (auto &arg : command)
    argv.push_back(arg.c_str());
  argv.push_back(nullptr);
  GError *error = nullptr;
  std::unique_ptr<GSubprocess, decltype(&g_object_unref)> child(
      g_subprocess_newv(argv.data(),
                        GSubprocessFlags(G_SUBPROCESS_FLAGS_STDOUT_PIPE |
                                         G_SUBPROCESS_FLAGS_STDERR_SILENCE),
                        &error),
      g_object_unref);
  if (!child) {
    if (error)
      g_error_free(error);
    throw std::runtime_error(
        "Cannot start the selected GnuPG engine; install gpg or gpgsm");
  }
  std::unique_ptr<GCancellable, decltype(&g_object_unref)> cancel(
      g_cancellable_new(), g_object_unref);
  std::mutex mutex;
  std::condition_variable changed;
  bool done = false;
  std::thread timeout([&] {
    std::unique_lock<std::mutex> lock(mutex);
    if (!changed.wait_for(lock, std::chrono::seconds(120),
                          [&] { return done; })) {
      g_cancellable_cancel(cancel.get());
      g_subprocess_force_exit(child.get());
    }
  });
  std::string output;
  bool failed = false;
  char buffer[4096];
  while (true) {
    auto count =
        g_input_stream_read(g_subprocess_get_stdout_pipe(child.get()), buffer,
                            sizeof buffer, cancel.get(), &error);
    if (count <= 0) {
      failed = count < 0;
      break;
    }
    output.append(buffer, size_t(count));
    if (output.size() > 2 * 1024 * 1024) {
      failed = true;
      g_subprocess_force_exit(child.get());
      break;
    }
  }
  bool ok =
      !failed && g_subprocess_wait_check(child.get(), cancel.get(), &error);
  {
    std::lock_guard<std::mutex> lock(mutex);
    done = true;
  }
  changed.notify_one();
  timeout.join();
  if (error)
    g_error_free(error);
  require(ok, "GnuPG operation failed, was canceled, or exceeded its "
              "output/time limit");
  return output;
}
std::string publicListing(const std::string &program) {
  if (program == "gpgsm")
    return gpg(program, {"--with-colons", "--list-keys"});
  return gpg(program, {"--with-colons", "--fixed-list-mode", "--fingerprint",
                       "--list-keys"});
}
void exportGpg(const std::string &program, const std::string &fingerprint,
               const fs::path &destination, bool secret) {
  require(!fingerprint.empty() &&
              fingerprint.find_first_not_of("0123456789ABCDEFabcdef") ==
                  std::string::npos,
          "Select a key fingerprint first");
  std::vector<std::string> args;
  if (program == "gpg" || !secret)
    args.push_back("--armor");
  args.push_back(secret ? (program == "gpgsm" ? "--export-secret-key-p12"
                                              : "--export-secret-keys")
                        : "--export");
  args.push_back("--");
  args.push_back(fingerprint);
  auto bytes = gpg(program, args, secret);
  require(!bytes.empty(), "The selected key is unavailable for export");
  writeNew(destination, bytes);
}
} // namespace identities
