// SPDX-License-Identifier: GPL-3.0-or-later
#include "identities.h"
#include <cassert>
#include <fstream>
#include <functional>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>
using namespace identities;
namespace {
bool fails(const std::function<void()> &operation) {
  try {
    operation();
    return false;
  } catch (const std::exception &) {
    return true;
  }
}
std::string read(const fs::path &path) {
  std::ifstream file(path, std::ios::binary);
  return std::string(std::istreambuf_iterator<char>(file), {});
}
} // namespace
int main() {
  char pattern[] = "/tmp/dome-identities-test-XXXXXX";
  char *folder = mkdtemp(pattern);
  assert(folder);
  fs::path root = folder;
  try {
    setenv("HOME", root.c_str(), 1);
    setenv("XDG_DATA_HOME", "relative-directory", 1);
    assert(catalogPath() == root / ".local/share/de-xr/identities/index.json");
    auto catalog = root / "data/de-xr/identities/index.json";
    for (const auto &name : std::vector<std::string>{
             " ", "\xc2\xa0", "bad\xc2\x85name", std::string("bad\xff")})
      assert(fails([&] { generate(catalog, name, "fixture@localhost"); }));
    for (const auto &address : std::vector<std::string>{
             "ž@localhost", "user@127.1", "user@0x7f000001", "user@example.123",
             "user@localhost\n"})
      assert(fails([&] { generate(catalog, "Fixture", address); }));
    assert(list(catalog)["identities"].empty());
    assert(fails([&] { generate(catalog, "Fixture", "bad/name@localhost"); }));
    assert(fails([&] { generate(catalog, "Fixture", "name@bad..host"); }));
    auto record = generate(catalog, "Fixture 世界", "fixture@localhost");
    auto certificate = record.at("certificate").get<std::string>(),
         key = record.at("key").get<std::string>(),
         id = record.at("id").get<std::string>();
    assert(fs::path(certificate) ==
           catalog.parent_path() / id / "certificate.pem");
    auto checked = inspect(certificate, key);
    assert(checked["address"] == "fixture@localhost" && checked["id"] == id &&
           checked["valid"] == true);
    auto encryptedCertificate = root / "encrypted-certificate.pem";
    auto encodedCertificate = read(certificate);
    encodedCertificate.insert(
        encodedCertificate.find('\n') + 1,
        "Proc-Type: 4,ENCRYPTED\nDEK-Info: "
        "AES-256-CBC,00000000000000000000000000000000\n\n");
    std::ofstream(encryptedCertificate) << encodedCertificate;
    assert(fails([&] { inspect(encryptedCertificate); }));
    auto backup = root / "identity-backup.pem";
    exportPemIdentity(catalog, id, backup);
    assert(inspect(backup, backup)["id"] == id);
    struct stat backupStat{};
    assert(stat(backup.c_str(), &backupStat) == 0 &&
           (backupStat.st_mode & 0777) == 0600);
    auto originalKey = read(key);
    assert(originalKey.find("PRIVATE KEY") != std::string::npos);
    struct stat st{};
    assert(stat(key.c_str(), &st) == 0 && (st.st_mode & 0777) == 0600);
    assert(stat(catalog.c_str(), &st) == 0 && (st.st_mode & 0777) == 0600);
    assert(stat(catalog.parent_path().c_str(), &st) == 0 &&
           (st.st_mode & 0777) == 0700);
    assert(read(catalog).find("PRIVATE KEY") == std::string::npos);
    adopt(catalog, "Updated name", certificate, key);
    assert(list(catalog)["identities"].size() == 1 &&
           list(catalog)["identities"][0]["name"] == "Updated name");
    auto publicFile = root / "public.pem";
    exportCertificate(catalog, id, publicFile);
    assert(read(publicFile).find("PRIVATE KEY") == std::string::npos &&
           inspect(publicFile)["id"] == id);
    assert(fails([&] { exportCertificate(catalog, id, publicFile); }));
    adopt(catalog, "Public certificate only", certificate, {});
    assert(list(catalog, true)["certificates"].size() == 1);
    assert(!list(catalog, true)["certificates"][0].contains("key"));
    exportCertificate(catalog, id, root / "public-only.pem", true);
    remove(catalog, id, true);
    assert(list(catalog, true)["certificates"].empty());
    chmod(key.c_str(), 0644);
    assert(fails([&] { adopt(catalog, "Unsafe", certificate, key); }));
    chmod(key.c_str(), 0600);
    chmod(certificate.c_str(), 0666);
    assert(
        fails([&] { adopt(catalog, "Unsafe certificate", certificate, key); }));
    chmod(certificate.c_str(), 0644);
    assert(fails([&] { exportPemIdentity(catalog, id, key); }));
    assert(read(key) == originalKey);
    auto keyLink = root / "linked.key";
    fs::create_symlink(key, keyLink);
    assert(fails([&] { inspect(certificate, keyLink); }));
    auto other = generate(catalog, "Other", "other@localhost");
    auto concurrent = root / "concurrent/index.json";
    fs::create_directory(concurrent.parent_path());
    chmod(concurrent.parent_path().c_str(), 0700);
    std::thread firstWriter([&] {
      for (int i = 0; i < 8; ++i)
        adopt(concurrent, "First writer", certificate, key);
    });
    std::thread secondWriter([&] {
      for (int i = 0; i < 8; ++i)
        adopt(concurrent, "Second writer",
              other.at("certificate").get<std::string>(),
              other.at("key").get<std::string>());
    });
    firstWriter.join();
    secondWriter.join();
    assert(list(concurrent)["identities"].size() == 2);
    assert(fails([&] {
      adopt(catalog, "Mismatch", certificate,
            other.at("key").get<std::string>());
    }));
    remove(catalog, id);
    assert(list(catalog)["identities"].size() == 1 &&
           read(key) == originalKey && fs::exists(certificate));
    auto international = generate(catalog, "Příliš 世界", "alice@příklad.cz");
    assert(international.at("address") == "alice@xn--pklad-zsa96e.cz");
    assert(inspect(
               international.at("certificate").get<std::string>())["address"] ==
           international["address"]);
    remove(catalog, international.at("id"));
    fs::path gnupg = root / "gnupg";
    fs::create_directory(gnupg);
    chmod(gnupg.c_str(), 0700);
    setenv("GNUPGHOME", gnupg.c_str(), 1);
    std::ofstream(gnupg / "gpg-agent.conf") << "pinentry-program /bin/false\n";
    auto listing = publicListing("gpg");
    assert(listing.find("pub:") == std::string::npos);
    // Fast fixture generation uses an empty passphrase and can never open
    // pinentry.
    gpg("gpg", {"--pinentry-mode", "loopback", "--passphrase", "",
                "--quick-generate-key", "--",
                "Fixture <fixture@example.invalid>", "ed25519", "sign", "1d"});
    listing = publicListing("gpg");
    assert(listing.find("fixture@example.invalid") != std::string::npos);
    auto fpr = listing.find("fpr:");
    assert(fpr != std::string::npos);
    auto start = listing.find(":::::::::", fpr);
    assert(start != std::string::npos);
    start += 9;
    auto end = listing.find(':', start);
    auto fingerprint = listing.substr(start, end - start);
    auto publicKey = root / "public.asc";
    exportGpg("gpg", fingerprint, publicKey, false);
    assert(read(publicKey).find("PUBLIC KEY BLOCK") != std::string::npos);
    auto secretKey = root / "secret.asc";
    exportGpg("gpg", fingerprint, secretKey, true);
    assert(stat(secretKey.c_str(), &st) == 0 && (st.st_mode & 0777) == 0600);
    auto kill = std::string("gpgconf --homedir '") + gnupg.string() +
                "' --kill gpg-agent";
    assert(system(kill.c_str()) == 0);
    fs::remove_all(root);
    puts("PASS isolated PEM identity creation, validation, catalog adoption, "
         "export, removal, permissions and GnuPG listing/generation/export");
    return 0;
  } catch (...) {
    fs::remove_all(root);
    throw;
  }
}
