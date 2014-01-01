//
// Part of Metta OS. Check http://metta.exquance.com for latest version.
//
// Copyright 2007 - 2014, Stanislav Karchebnyy <berkus@exquance.com>
//
// Distributed under the Boost Software License, Version 1.0.
// (See file LICENSE_1_0.txt or a copy at http://www.boost.org/LICENSE_1_0.txt)
//
#include <regex>
#include "client_profile.h"

namespace uia {
namespace routing {

std::vector<std::string>
client_profile::keywords() const
{
    std::vector<std::string> result;
    std::regex word_regex("(\\S+)");

    for (auto tag : tags())
    {
        if (tag & to_underlying(attribute_tag::searchable))
        {
            std::string s = string(attribute_tag(tag));
            // Break this string into keywords and add it to our list
            auto words_begin = std::sregex_iterator(s.begin(), s.end(), word_regex);
            auto words_end = std::sregex_iterator();

            const int N = 2;
            for (std::sregex_iterator i = words_begin; i != words_end; ++i) {
                std::smatch match = *i;
                std::string match_str = match.str();
                if (match_str.size() >= N) {
                    result.emplace_back(match_str);
                }
            }
        }
    }
    return result;
}

std::vector<ssu::endpoint>
client_profile::endpoints() const
{
    std::vector<ssu::endpoint> result;
    {
        byte_array_iwrap<flurry::iarchive> read(attribute(attribute_tag::endpoints));
        read.archive() >> result;
    }
    return result;
}

void
client_profile::set_endpoints(std::vector<ssu::endpoint> const& endpoints)
{
    byte_array buf;
    {
        byte_array_owrap<flurry::oarchive> write(buf);
        write.archive() << endpoints;
    }
    set_attribute(attribute_tag::endpoints, buf);
}

} // routing namespace
} // uia namespace
