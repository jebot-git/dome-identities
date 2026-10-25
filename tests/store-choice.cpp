// SPDX-License-Identifier: GPL-3.0-or-later
#include "store-choice.h"
#include <cassert>
#include <cstring>
int main() {
  Fl_Choice choice(0, 0, 400, 30);
  dx::identityStores(choice);
  assert(choice.size() == 5); // Four leaves and the terminating item.
  for (int index = 0; index < 4; ++index) {
    assert(choice.menu()[index].label());
    assert(!choice.menu()[index].submenu());
    assert(choice.menu()[index].active());
  }
  assert(!strcmp(choice.menu()[3].label(), "S/MIME certificates (gpgsm)"));
  choice.value(3);
  assert(choice.value() == 3 && choice.mvalue() == &choice.menu()[3]);
}
