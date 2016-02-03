// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (C) 2012-2016, Ryan P. Wilson
//
//      Authority FX, Inc.
//      www.authorityfx.com

#include "licensegenerator.h"

#include <ippcore.h>
#include <ippcp.h>
#include <cstring>
#include <iostream> //for debugging
#include <iomanip>
#include <algorithm>
#include <exception>
#include <cstdlib>
#include <ctime>

RandomText::RandomText() {
  std::string temp = "0123456789abcdefghijklmnopqrstuvwxyz";
  strcpy(alpha_num_, temp.c_str());
}
std::string RandomText::Generate(int length) {
  std::stringstream ss;
  for (int i = 0; i < length; ++i) {
      ss << alpha_num_[rand() % (sizeof(alpha_num_) - 1)];
  }
  return ss.str();
}
std::string RandomText::Generate(int min_lenth, int max_length) {
  srand(std::time(NULL));
  return Generate(rand() % (max_length - min_lenth) + min_lenth);
}

void LicenseGenerator::SetUUID1(std::string uuid1) { uuid1_ = uuid1; }
void LicenseGenerator::SetUUID2(std::string uuid2) { uuid2_ = uuid2; }
void LicenseGenerator::AddPlugin(std::string name, LicenseType type, int count, int floating) {
  plugins_ << name << "[" << type << "," << count << "," << floating << "]";
  num_plugs_++;
}

int LicenseGenerator::ParseInput(std::string input) {
  size_t start;
  size_t end;

  //convert to lowercase
  std::transform(input.begin(), input.end(), input.begin(), ::tolower);
  //remove whitespace
  std::remove_if(input.begin(), input.end(), ::isspace);

  //Num of plugins
  start = input.find("num_plugs={") + 11;
  if ( start == std::string::npos) { return 1; }
  end = input.find_first_of("}", start) - 1;

  int num_plugs;

  try {
    std::stringstream ss(input.substr(start, end));
    ss >> num_plugs;
    if (num_plugs < 1) { return 1; }
  } catch(std::exception e) { return 1; }

  //Find plugins
  start = input.find("plugins={") + 9;
  end = input.find_first_of("}", start) - 1;
  if ( start == std::string::npos) { return 1; }

  std::string plugins = input.substr(start, end - start + 1);

  start = 0;
  for (int i = 0; i < num_plugs; i++) {
    std::string name;
    int type;
    int count;
    int floating;

    //Find name
    end = plugins.find_first_of("[", start) - 1;
    name = plugins.substr(start, end - start + 1);
    if (name.length() < 1) { return 1; }

    //Find type
    start = end + 2;
    end = plugins.find_first_of(",", start) - 1;
    try {
        std::stringstream ss(plugins.substr(start, end - start + 1));
        ss >> type;
    } catch(std::exception e) { return 1; }
    //Find count
    start = end + 2;
    end = plugins.find_first_of(",", start) - 1;
    try {
        std::stringstream ss(plugins.substr(start, end - start + 1));
        ss >> count;
    } catch(std::exception e) { return 1; }

    //Find floating
    start = end + 2;
    end = plugins.find_first_of("]", start) - 1;
    try {
        std::stringstream ss(plugins.substr(start, end - start + 1));
        ss >> floating;
    } catch(std::exception e) { return 1; }

    //add plugin to license
    AddPlugin(name, (LicenseType)type, count, floating);

    start = end + 2;
  }

  //Find uuid1 address
  start = input.find("uuid1={") + 7;
  end = input.find_first_of("}", start) - start;
  if ( start == std::string::npos) { return 1; }

  std::string uuid1 = input.substr(start, end);
  if (uuid1.length() < 1) { return 1; }
  SetUUID1(uuid1);

  //Find uuid2 uuid
  start = input.find("uuid2={") + 7;
  end = input.find_first_of("}", start) - start;
  if ( start == std::string::npos) { return 1; }

  std::string uuid2 = input.substr(start, end);
  if (uuid2.length() < 1) { return 1; }
  SetUUID2(uuid2);

  return 0;
}

std::string LicenseGenerator::EncryptLicense() {
  //Initialize omp threading
  ippInit();

  RandomText text_generator;

  //Build licecse
  std::stringstream license;
  license << text_generator.Generate(10, 20);
  license << "num_plugs={"    << num_plugs_       << "}";
  license << "plugins={"      << plugins_.str()   << "}";
  license << "uuid1={"        << uuid1_           << "}";
  license << "uuid2={"        << uuid2_           << "}";

  int license_size = license.str().size();

  Ipp8u plain[license_size];
  for (int i = 0; i < license_size; i++) { plain[i] = license.str().at(i); }

  const int blkSize = 16;
  int ctxSize;
  ippsRijndael128GetSize(&ctxSize);

  // allocate memory for Rijndael context
  IppsRijndael128Spec* ctx = (IppsRijndael128Spec*)( new Ipp8u [ctxSize] );

  // 256-bit key
  Ipp8u key[32] = {
      0xc3,0x78,0x09,0x9a,0x15,0xd1,0xae,0x28,
      0xf0,0xa3,0x32,0x80,0x82,0xe4,0xa9,0x43,
      0x47,0xe0,0xa7,0xf5,0xbb,0xf9,0x02,0xe5,
      0xc8,0xc3,0x2a,0xf5,0x6d,0x56,0x73,0xad
  };

  // counter
  Ipp8u ctr0[blkSize] = {
      0x29,0xe3,0x65,0x6c,0xe4,0xee,0x02,0x92,
      0x8c,0x3d,0x22,0xa4,0x5e,0xbf,0xdb,0x64
  };

  // Rijndael context initialization
  ippsRijndael128Init(key, IppsRijndaelKey256, ctx);


  Ipp8u ctr[blkSize];
  memcpy(ctr,ctr0,sizeof(ctr0));

  int ctrNumBitSize = 64;

  // cipher text array of size equal to plain text size
  Ipp8u ciph[license_size];

  // encrypting plain text
  ippsRijndael128EncryptCTR(plain, ciph, license_size, ctx, ctr, ctrNumBitSize);

  Ipp8u deciph[license_size];
  memcpy(ctr,ctr0,sizeof(ctr0));
  ippsRijndael128EncryptCTR(ciph, deciph, license_size, ctx, ctr, ctrNumBitSize);

  std::stringstream ss;

  //hash plain
  Ipp8u hash[20];
  ippsSHA1MessageDigest(deciph, license_size, hash);

  //Insert encrypted license into ss
  for (int i = 0; i < license_size; i++) {
      ss << std::setw(2) << std::setfill('0') << std::hex << (unsigned int)ciph[i];
  }

  //Insert hash into ss
  for (int i = 0; i < 20; i++) {
      ss << std::setw(2) << std::setfill('0') << std::hex << (unsigned int)hash[i];
  }

  return ss.str();
}
