// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (C) 2012-2016, Ryan P. Wilson
//
//      Authority FX, Inc.
//      www.authorityfx.com

#ifndef LICENSEGEN_H_
#define LICENSEGEN_H_

#include <string>
#include <sstream>

enum LicenseType {
  L_WORKSTATION,
  L_RENDER,
  L_TRIAL
};

class RandomText {
private:
  char alpha_num_[37];
public:
  RandomText();
  std::string Generate(int min_length, int max_length);
  std::string Generate(int length);
};

class LicenseGenerator {
private:
  int num_plugs_;
  std::stringstream plugins_;
  std::string uuid2_;
  std::string uuid1_;
public:
  LicenseGenerator() {num_plugs_ = 0;};
  void AddPlugin(std::string name, LicenseType type, int count, int floating);
  int ParseInput(std::string input);
  void SetUUID1(std::string uuid1);
  void SetUUID2(std::string uuid2);
  std::string EncryptLicense();
};

#endif // LICENSEGEN_H_
