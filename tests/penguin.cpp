// SPDX-License-Identifier: GPL-3.0-or-later
#include "identities.h"
#include <cassert>
#include <fcntl.h>
#include <fstream>
#include <functional>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>
using namespace identities;
namespace {
std::string readFile(const fs::path &path) {
  std::ifstream file(path, std::ios::binary);
  return std::string(std::istreambuf_iterator<char>(file), {});
}
void writePrivate(const fs::path &path, const std::string &bytes) {
  int file = open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
  assert(file >= 0);
  assert(write(file, bytes.data(), bytes.size()) == ssize_t(bytes.size()));
  assert(close(file) == 0);
}
bool fails(const std::function<void()> &action) {
  try { action(); return false; } catch (const std::exception &) { return true; }
}
void privateMode(const fs::path &path, int expected) {
  struct stat status{};
  assert(lstat(path.c_str(), &status) == 0);
  assert(status.st_uid == geteuid() && (status.st_mode & 0777) == expected);
}
} // namespace
int main() {
  char pattern[] = "/tmp/dome-penguin-import-XXXXXX";
  char *temporary = mkdtemp(pattern); assert(temporary);
  fs::path root = temporary;
  try {
    setenv("HOME", root.c_str(), 1);
    setenv("XDG_DATA_HOME", root.c_str(), 1);
    auto source = penguinStorePath();
    assert(source == root / "penguin-mail/misfin/state.json");
    assert(penguinIdentities(source).empty());
    fs::create_directories(source.parent_path());
    chmod(source.parent_path().c_str(), 0700);
    auto first = generate(root / "fixtures/index.json", "First", "first@localhost");
    auto second = generate(root / "fixtures/index.json", "Second", "second@localhost");
    auto firstId = first.at("id").get<std::string>();
    auto secondId = second.at("id").get<std::string>();
    Json state = {{"identities", Json::array({
      {{"id", firstId}, {"address", "untrusted@example.invalid"},
       {"certificate", readFile(first.at("certificate").get<std::string>())},
       {"key", "unavailable"}},
      {{"id", secondId}, {"address", "untrusted@example.invalid"},
       {"certificate", readFile(second.at("certificate").get<std::string>())},
       {"key", readFile(second.at("key").get<std::string>())}}
    })}, {"messages", Json::array()}, {"pins", Json::object()}};
    writePrivate(source, state.dump());
    auto sourceBytes = readFile(source);
    auto catalog = root / "shared/index.json";
    auto available = penguinIdentities(source);
    assert(available.size() == 2);
    assert(available[0].at("address") == "first@localhost");
    assert(available[1].at("address") == "second@localhost");
    assert(available.dump().find("PRIVATE KEY") == std::string::npos);
    assert(!available[0].contains("key") && !available[0].contains("certificate"));
    assert(!fs::exists(catalog)); // Listing never publishes an identity.
    assert(fails([&] { importPenguinIdentity(catalog, source, firstId, "First"); }));
    assert(!fs::exists(catalog));
    auto imported = importPenguinIdentity(catalog, source, secondId, "Chosen identity 世界");
    assert(imported.at("id") == secondId && imported.at("address") == "second@localhost");
    assert(imported.at("name") == "Chosen identity 世界");
    auto certificate = fs::path(imported.at("certificate").get<std::string>());
    auto key = fs::path(imported.at("key").get<std::string>());
    assert(certificate == catalog.parent_path() / secondId / "certificate.pem");
    assert(key == catalog.parent_path() / secondId / "key.pem");
    assert(inspect(certificate, key).at("id") == secondId);
    assert(readFile(key) == state["identities"][1]["key"]);
    assert(readFile(source) == sourceBytes);
    privateMode(source, 0600); privateMode(catalog, 0600);
    privateMode(catalog.parent_path(), 0700); privateMode(key.parent_path(), 0700);
    privateMode(certificate, 0600); privateMode(key, 0600);
    assert(readFile(catalog).find("PRIVATE KEY") == std::string::npos);
    auto catalogBytes = readFile(catalog), keyBytes = readFile(key);
    // Repeat imports preserve an existing name and file references.
    assert(importPenguinIdentity(catalog, source, secondId, "Replacement") == imported);
    assert(readFile(catalog) == catalogBytes && readFile(key) == keyBytes);
    remove(catalog, secondId); // Removing a reference intentionally keeps PEM files.
    assert(importPenguinIdentity(catalog, source, secondId, "Imported again").at("id") == secondId);
    assert(readFile(key) == keyBytes);
    chmod(source.c_str(), 0644);
    assert(fails([&] { penguinIdentities(source); }));
    assert(fails([&] { importPenguinIdentity(catalog, source, secondId, "Unsafe source"); }));
    chmod(source.c_str(), 0600);
    auto link = root / "linked-state.json"; fs::create_symlink(source, link);
    assert(fails([&] { penguinIdentities(link); }));
    writePrivate(source, "{PRIVATE KEY INPUT THAT MUST NOT APPEAR IN ERRORS");
    try { penguinIdentities(source); assert(false); }
    catch (const std::exception &error) {
      assert(std::string(error.what()) == "Invalid Penguin Mail identity store");
    }
    state["identities"][1]["certificate"] = state["identities"][0]["certificate"];
    writePrivate(source, state.dump());
    assert(penguinIdentities(source).size() == 1);
    assert(fails([&] { importPenguinIdentity(catalog, source, secondId, "Changed"); }));
    writePrivate(source, std::string(8 * 1024 * 1024 + 1, ' '));
    assert(fails([&] { penguinIdentities(source); }));
    // A failed catalog publication removes only files created by that import.
    state["identities"][0]["key"] = readFile(first.at("key").get<std::string>());
    writePrivate(source, state.dump());
    auto broken = root / "broken/index.json"; fs::create_directories(broken.parent_path());
    writePrivate(broken, "{}");
    assert(fails([&] { importPenguinIdentity(broken, source, firstId, "First"); }));
    assert(!fs::exists(broken.parent_path() / firstId));
    fs::remove_all(root);
    puts("PASS explicit selected Penguin import, public-only metadata, unchanged source, "
         "private PEM copies, existing references, repeat/removal handling and invalid input rejection");
  } catch (...) { fs::remove_all(root); throw; }
}
