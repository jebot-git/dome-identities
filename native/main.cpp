// SPDX-License-Identifier: GPL-3.0-or-later
#include "desktop-menu.h"
#include "gpu-window.h"
#include "identities.h"
#include "status-icon.h"
#include <FL/Fl_Hold_Browser.H>
#include <FL/Fl_Native_File_Chooser.H>
#include <FL/Fl_Tabs.H>
#include <FL/Fl_Text_Display.H>
#include <FL/fl_ask.H>
#include <chrono>
#include <functional>
#include <gio/gio.h>
#include <mutex>
#include <sstream>
#include <thread>
using identities::Json;
namespace fs = std::filesystem;
namespace {
std::string literal(const std::string &text) {
  std::string out;
  for (char c : text) {
    out += c;
    if (c == '@')
      out += '@';
  }
  return out;
}
std::string choose(const char *title, bool save = false) {
  Fl_Native_File_Chooser dialog;
  dialog.title(title);
  dialog.type(save ? Fl_Native_File_Chooser::BROWSE_SAVE_FILE
                   : Fl_Native_File_Chooser::BROWSE_FILE);
  return dialog.show() ? "" : dialog.filename();
}
Json keyRows(const std::string &program) {
  auto output = identities::publicListing(program);
  Json records = Json::array();
  Json record;
  std::istringstream lines(output);
  std::string line;
  while (std::getline(lines, line)) {
    std::vector<std::string> fields;
    std::istringstream input(line);
    std::string field;
    while (std::getline(input, field, ':'))
      fields.push_back(field);
    if (fields.size() < 10)
      continue;
    if (fields[0] == "pub" || fields[0] == "crt") {
      if (!record.is_null() && record.contains("id"))
        records.push_back(record);
      record = {{"name", fields[4]}, {"kind", fields[0]}};
    } else if (fields[0] == "fpr" && !record.is_null() &&
               !record.contains("id"))
      record["id"] = fields[9];
    else if (fields[0] == "uid" && !record.is_null())
      record["name"] = fields[9];
  }
  if (!record.is_null() && record.contains("id"))
    records.push_back(record);
  return records;
}
class Manager : public dx::GpuWindow {
  DesktopMenuBar menu{0, 0, 1100, 30};
  Fl_Choice kind{150, 15, 365, 34, "Identity store:"};
  Fl_Box location{20, 60, 1050, 40};
  Fl_Hold_Browser rows{20, 115, 430, 390};
  Fl_Text_Display details{470, 115, 610, 390};
  Fl_Text_Buffer detailBuffer;
  Fl_Button refresh{20, 525, 120, 34, "Refresh"},
      import{155, 525, 130, 34, "Import..."},
      create{300, 525, 150, 34, "Create..."};
  Fl_Button publicExport{470, 525, 185, 34, "Export public..."},
      secretExport{670, 525, 190, 34, "Export secret..."},
      remove{875, 525, 205, 34, "Remove..."};
  Fl_Box status{20, 580, 1060, 45};
  std::unique_ptr<DesktopMenu> desktop;
  std::unique_ptr<StatusIcon> tray;
  Json records = Json::array();
  std::thread worker;
  std::mutex resultMutex;
  bool busy = false;
  std::string feedback;
  const fs::path catalog = identities::catalogPath();
  struct Result {
    Json records;
    std::string error;
  };
  std::unique_ptr<Result> completed;
  std::string program() const { return kind.value() == 3 ? "gpgsm" : "gpg"; }
  void say(std::string text) {
    feedback = literal(text);
    status.copy_label(feedback.c_str());
    redraw();
  }
  Json selected() {
    int row = rows.value() - 1;
    if (row < 0 || size_t(row) >= records.size())
      throw std::runtime_error("Select an identity first");
    return records[size_t(row)];
  }
  Json load(int store) {
    if (store == 0)
      return identities::list(catalog).at("identities");
    if (store == 1)
      return identities::list(catalog, true).at("certificates");
    return keyRows(store == 3 ? "gpgsm" : "gpg");
  }
  void updateCommands() {
    for (const char *name : {"Import...", "Refresh", "Export public...",
                             "Remove...", "Quit"})
      menu.mode(menu.find_index(name), busy ? FL_MENU_INACTIVE : 0);
    menu.mode(menu.find_index("Create..."),
              busy || kind.value() == 1 || kind.value() == 3 ? FL_MENU_INACTIVE : 0);
    menu.mode(menu.find_index("Export secret..."),
              busy || kind.value() == 1 ? FL_MENU_INACTIVE : 0);
  }
  void execute(std::function<void()> action = {}) {
    if (busy) {
      say("Finish the current identity operation first.");
      return;
    }
    busy = true;
    updateCommands();
    kind.deactivate();
    int store = kind.value();
    say("Working... GnuPG may open its passphrase dialog for an action you "
        "requested.");
    try {
      worker = std::thread([this, store, action] {
        auto result = std::make_unique<Result>(Result{Json::array(), ""});
        try {
          if (action)
            action();
          result->records = load(store);
        } catch (const std::exception &e) {
          result->error = e.what();
        }
        {
          std::lock_guard<std::mutex> lock(resultMutex);
          completed = std::move(result);
        }
        Fl::awake();
      });
    } catch (const std::exception &) {
      busy = false;
      updateCommands();
      kind.activate();
      say("Cannot start the identity worker.");
    }
  }

  void changed() {
    if (busy)
      return;
    records = Json::array();
    rows.clear();
    detailBuffer.text("");
    bool pem = kind.value() < 2;
    secretExport.activate();
    create.activate();
    if (kind.value() == 1)
      secretExport.deactivate();
    if (kind.value() == 1 || kind.value() == 3)
      create.deactivate();
    auto path =
        pem ? (kind.value() == 1
                   ? (catalog.parent_path() / "certificates.json").string()
                   : catalog.string())
            : std::string(getenv("GNUPGHOME")
                              ? getenv("GNUPGHOME")
                              : "GnuPG default keyring (~/.gnupg)");
    location.copy_label(literal(path).c_str());
    execute();
  }
  void showSelected() {
    try {
      auto record = selected();
      std::string text =
          "Fingerprint: " + record.at("id").get<std::string>() + "\n";
      if (kind.value() < 2) {
        auto checked =
            identities::inspect(record.at("certificate").get<std::string>());
        if (checked.at("id") != record.at("id"))
          throw std::runtime_error(
              "Certificate fingerprint changed; reimport it before use");
        text += "Certificate: " + record.at("certificate").get<std::string>() +
                "\nPrivate key: " +
                record.value("key", "None (public certificate)") + "\n" +
                checked.at("details").get<std::string>();
      } else
        text += "Name: " + record.value("name", "") +
                "\n\nPublic listing only. Secret key export and deletion are "
                "separate explicit actions.\n";
      detailBuffer.text(text.c_str());
    } catch (const std::exception &e) {
      say(e.what());
    }
  }
  void importIdentity() {
    if (busy)
      return;
    try {
      if (kind.value() < 2) {
        bool publicOnly = kind.value() == 1;
        auto cert = choose(publicOnly ? "Public certificate PEM"
                                      : "Identity certificate PEM");
        if (cert.empty())
          return;
        auto key =
            publicOnly
                ? std::string()
                : choose("Matching owner-only unencrypted PEM private key");
        if (!publicOnly && key.empty())
          return;
        const char *name = fl_input("Identity display name:");
        if (!name)
          return;
        std::string label = name;
        execute([=] {
          identities::adopt(catalog, label, fs::absolute(cert),
                            publicOnly ? fs::path() : fs::absolute(key));
        });
      } else {
        auto path = choose(kind.value() == 3
                               ? "Import S/MIME certificate or PKCS#12 identity"
                               : "Import OpenPGP public or secret key");
        if (path.empty())
          return;
        auto engine = program();
        execute([=] {
          identities::gpg(
              engine, {"--import", "--", fs::absolute(path).string()}, true);
        });
      }
    } catch (const std::exception &e) {
      say(e.what());
    }
  }
  void createIdentity() {
    if (kind.value() == 1 || kind.value() == 3) {
      say("Import an existing certificate or identity for this store.");
      return;
    }
    if (busy)
      return;
    const char *entered =
        fl_input(kind.value() == 0 ? "Identity display name:"
                                   : "OpenPGP user ID (name and email):");
    if (!entered)
      return;
    std::string name = entered;
    if (kind.value() == 0) {
      const char *enteredAddress = fl_input(
          "Misfin mailbox@@DNS hostname (provider registration is separate):");
      if (!enteredAddress)
        return;
      std::string address = enteredAddress;
      execute([=] { identities::generate(catalog, name, address); });
    } else if (kind.value() == 2)
      execute([=] {
        identities::gpg(
            "gpg",
            {"--quick-generate-key", "--", name, "default", "default", "2y"},
            true);
      });
  }
  void exportIdentity(bool secret) {
    if (secret && kind.value() == 1) return;
    if (busy)
      return;
    try {
      auto record = selected();
      auto id = record.at("id").get<std::string>();
      if (secret &&
          fl_choice("Export the selected secret key? Store the "
                    "resulting file securely.\nThe destination must "
                    "be a new file with owner-only permissions.\nPEM identity "
                    "backups contain an unencrypted private key.",
                    "Cancel", "Export secret key", nullptr) != 1)
        return;
      auto path =
          choose(secret ? "Export secret key to a new file"
                        : "Export public certificate or key to a new file",
                 true);
      if (path.empty())
        return;
      auto engine = program();
      bool pem = kind.value() < 2;
      bool publicOnly = kind.value() == 1;
      execute([=] {
        if (pem && secret)
          identities::exportPemIdentity(catalog, id, path);
        else if (pem)
          identities::exportCertificate(catalog, id, path, publicOnly);
        else
          identities::exportGpg(engine, id, path, secret);
      });
    } catch (const std::exception &e) {
      say(e.what());
    }
  }
  void removeIdentity() {
    if (busy)
      return;
    try {
      auto record = selected();
      auto id = record.at("id").get<std::string>();
      if (kind.value() < 2) {
        bool publicOnly = kind.value() == 1;
        if (fl_choice("Remove this identity from the shared "
                      "catalog?\nCertificate and key files remain on disk, "
                      "including files used by other apps.",
                      "Cancel", "Remove reference", nullptr) != 1)
          return;
        execute([=] { identities::remove(catalog, id, publicOnly); });
      } else {
        auto engine = program();
        int choice = fl_choice(
            "Remove the selected key from your GnuPG keyring?\nSecret-key "
            "deletion is permanent. Export a secure backup first.",
            "Cancel", "Public key only",
            kind.value() == 2 ? "Secret and public" : nullptr);
        if (choice <= 0)
          return;
        execute([=] {
          identities::gpg(engine,
                          {"--yes",
                           choice == 2 ? "--delete-secret-and-public-keys"
                                       : "--delete-keys",
                           "--", id},
                          choice == 2);
        });
      }
    } catch (const std::exception &e) {
      say(e.what());
    }
  }
  void quit() {
    if (busy) {
      say("Finish the current operation before quitting.");
      return;
    }
    hide();
    exitRequested = true;
  }

public:
  bool exitRequested = false;
  int handle(int event) override {
    if (event == FL_SHORTCUT && menu.test_shortcut()) return 1;
    return dx::GpuWindow::handle(event);
  }
  void poll() {
    std::unique_ptr<Result> result;
    {
      std::lock_guard<std::mutex> lock(resultMutex);
      result = std::move(completed);
    }
    if (!result)
      return;
    if (worker.joinable())
      worker.join();
    busy = false;
    updateCommands();
    kind.activate();
    if (!result->error.empty()) {
      say(result->error);
      return;
    }
    records = std::move(result->records);
    rows.clear();
    for (auto &record : records)
      rows.add(literal(record.value("name", "") + "  " +
                       record.value("id", "").substr(0, 12))
                   .c_str());
    detailBuffer.text("");
    say("Ready. Identity use and key changes require an explicit action.");
  }
  bool trayAvailable() const { return tray && tray->available(); }
  Manager() : dx::GpuWindow(1100, 650, "Dome Identities") {
    xclass("org.domed.Identities");
    kind.add("Shared PEM identities|Public PEM certificates|OpenPGP "
             "(GnuPG)|S/MIME certificates (gpgsm)");
    kind.value(0);
    location.align(FL_ALIGN_LEFT | FL_ALIGN_INSIDE | FL_ALIGN_WRAP);
    status.align(FL_ALIGN_LEFT | FL_ALIGN_INSIDE | FL_ALIGN_WRAP);
    details.buffer(detailBuffer);
    details.wrap_mode(Fl_Text_Display::WRAP_AT_BOUNDS, 0);
    rows.when(FL_WHEN_CHANGED);
    kind.callback(
        [](Fl_Widget *, void *p) { static_cast<Manager *>(p)->changed(); },
        this);
    rows.callback(
        [](Fl_Widget *, void *p) { static_cast<Manager *>(p)->showSelected(); },
        this);
    refresh.callback(
        [](Fl_Widget *, void *p) { static_cast<Manager *>(p)->execute(); },
        this);
    import.callback(
        [](Fl_Widget *, void *p) {
          static_cast<Manager *>(p)->importIdentity();
        },
        this);
    create.callback(
        [](Fl_Widget *, void *p) {
          static_cast<Manager *>(p)->createIdentity();
        },
        this);
    publicExport.callback(
        [](Fl_Widget *, void *p) {
          static_cast<Manager *>(p)->exportIdentity(false);
        },
        this);
    secretExport.callback(
        [](Fl_Widget *, void *p) {
          static_cast<Manager *>(p)->exportIdentity(true);
        },
        this);
    remove.callback(
        [](Fl_Widget *, void *p) {
          static_cast<Manager *>(p)->removeIdentity();
        },
        this);
    menu.add(
        "Show identities", FL_CTRL | 'o',
        [](Fl_Widget *, void *p) { static_cast<Manager *>(p)->show(); }, this);
    menu.add(
        "Import...", FL_CTRL | 'i',
        [](Fl_Widget *, void *p) {
          static_cast<Manager *>(p)->importIdentity();
        },
        this);
    menu.add(
        "Create...", FL_CTRL | 'n',
        [](Fl_Widget *, void *p) {
          static_cast<Manager *>(p)->createIdentity();
        },
        this);
    menu.add(
        "Refresh", FL_F + 5,
        [](Fl_Widget *, void *p) { static_cast<Manager *>(p)->execute(); },
        this);
    menu.add("Export public...", 0, [](Fl_Widget *, void *p) { static_cast<Manager *>(p)->exportIdentity(false); }, this);
    menu.add("Export secret...", 0, [](Fl_Widget *, void *p) { static_cast<Manager *>(p)->exportIdentity(true); }, this);
    menu.add("Remove...", 0, [](Fl_Widget *, void *p) { static_cast<Manager *>(p)->removeIdentity(); }, this);
    menu.add(
        "Close to tray", FL_META | 'w',
        [](Fl_Widget *, void *p) {
          auto s = static_cast<Manager *>(p);
          if (s->tray && s->tray->available())
            s->hide();
          else
            s->quit();
        },
        this);
    menu.add(
        "Quit", FL_META | 'q',
        [](Fl_Widget *, void *p) { static_cast<Manager *>(p)->quit(); }, this);
    end();
    resizable(details);
    size_range(1000, 620);
    callback(
        [](Fl_Widget *, void *p) {
          auto s = static_cast<Manager *>(p);
          if (s->tray && s->tray->available())
            s->hide();
          else
            s->quit();
        },
        this);
    // Tray ownership supplies the command menu; the identity window has only
    // its native controls and shortcuts, with no separate File/menu bar.
    menu.hide();
    desktop = std::make_unique<DesktopMenu>(*this, menu, false);
    tray = std::make_unique<StatusIcon>(*desktop);
    tray->setTitle("Dome Identities");
    tray->activate = [this] { show(); };
    dx::style(this);
    changed();
  }
  ~Manager() {
    if (worker.joinable())
      worker.join();
    // The buffer member is destroyed before the display member.
    details.buffer(nullptr);
  }
};
} // namespace
int main(int argc, char **argv) try {
  bool trayOnly = false;
  for (int i = 1; i < argc; ++i) {
    if (std::string(argv[i]) == "--tray")
      trayOnly = true;
    else if (std::string(argv[i]) == "--help") {
      puts("Dome Identities [--tray]\nNative shared PEM, OpenPGP and S/MIME "
           "identity manager.");
      return 0;
    } else
      throw std::runtime_error("Unknown option");
  }
  Fl::lock();
  dx::init();
  Manager window;
  if (!trayOnly)
    window.show();
  while (!window.exitRequested) {
    Fl::wait(.05);
    window.poll();
    while (g_main_context_iteration(nullptr, FALSE)) {
    }
    if (!window.shown())
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
    if (trayOnly) {
      static int attempts = 0;
      if (window.trayAvailable())
        trayOnly = false;
      else if (++attempts == 40) {
        window.show();
        trayOnly = false;
      }
    }
  }
  return 0;
} catch (const std::exception &e) {
  fprintf(stderr, "Dome Identities: %s\n", e.what());
  return 1;
}
