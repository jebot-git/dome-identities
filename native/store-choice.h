// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <FL/Fl_Choice.H>
namespace dx {
inline void identityStores(Fl_Choice &choice) {
  choice.add("Shared PEM identities|Public PEM certificates|OpenPGP "
             "(GnuPG)|S-MIME certificates (gpgsm)");
  // Fl_Menu_::add treats '/' as a submenu separator. Replace the label
  // afterwards so S/MIME remains one selectable store, rather than an S menu.
  choice.replace(3, "S/MIME certificates (gpgsm)");
}
} // namespace dx
