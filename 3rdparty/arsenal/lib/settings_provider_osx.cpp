//
// Part of Metta OS. Check https://metta.systems for latest version.
//
// Copyright 2007 - 2017, Stanislav Karchebnyy <berkus@metta.systems>
//
// Distributed under the Boost Software License, Version 1.0.
// (See file LICENSE_1_0.txt or a copy at http://www.boost.org/LICENSE_1_0.txt)
//
// OSX version
// Save config to ~/Library/Preferences/<orgdomain>.<appname>.config
//
#include <string>
#include <sstream>

namespace arsenal::detail
{

std::string settings_file_name(std::string orgname, std::string orgdomain, std::string appname)
{
    std::ostringstream os;
    os << getenv("HOME") << "/Library/Preferences/";
    os << orgdomain << "." << appname << ".config";
    return os.str();
}

} // arsenal::detail namespace
