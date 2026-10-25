// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <filesystem>
#include <nlohmann/json.hpp>
#include <string>
#include <vector>
namespace identities {
namespace fs = std::filesystem;
using Json = nlohmann::json;
fs::path catalogPath();
fs::path penguinStorePath();
Json penguinIdentities(const fs::path &store);
Json importPenguinIdentity(const fs::path &catalog, const fs::path &store,
                           const std::string &id, const std::string &name);
Json inspect(const fs::path &certificate, const fs::path &key = {});
Json list(const fs::path &catalog, bool publicOnly = false);
Json adopt(const fs::path &catalog, const std::string &name,
           const fs::path &certificate, const fs::path &key);
Json generate(const fs::path &catalog, const std::string &name,
              const std::string &address);
void remove(const fs::path &catalog, const std::string &id,
            bool publicOnly = false);
void exportCertificate(const fs::path &catalog, const std::string &id,
                       const fs::path &destination, bool publicOnly = false);
void exportPemIdentity(const fs::path &catalog, const std::string &id,
                       const fs::path &destination);
std::string gpg(const std::string &program,
                const std::vector<std::string> &args, bool mayAsk = false);
std::string publicListing(const std::string &program);
void exportGpg(const std::string &program, const std::string &fingerprint,
               const fs::path &destination, bool secret);
} // namespace identities
