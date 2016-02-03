// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (C) 2012-2016, Ryan P. Wilson
//
//      Authority FX, Inc.
//      www.authorityfx.com

#include <iostream>
#include <licensegenerator.h>

int main(int argc, char **argv) {
  if (argc == 2) {
    std::stringstream input;
    input << argv[1];

    LicenseGenerator license;

    if (license.ParseInput(input.str()) == 0) {
        std::cout << license.EncryptLicense() << std::endl;
    } else {
        std::cerr << "Parse Error";
        return 1;
    }
  } else {
      std::cerr << "Incorrect Paramters";
      return 1;
  }
  return 0;
}
