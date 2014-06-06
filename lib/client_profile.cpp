//
// Part of Metta OS. Check http://atta-metta.net for latest version.
//
// Copyright 2007 - 2014, Stanislav Karchebnyy <berkus@atta-metta.net>
//
// Distributed under the Boost Software License, Version 1.0.
// (See file LICENSE_1_0.txt or a copy at http://www.boost.org/LICENSE_1_0.txt)
//
#include <regex>
#include <vector>
#include <string>
#include "routing/client_profile.h"

using namespace std;

namespace uia {
namespace routing {

vector<string>
client_profile::keywords() const
{
    vector<std::string> result;
    regex word_regex("(\\S+)");

    for (auto tag : tags())
    {
        if (tag & to_underlying(attribute_tag::searchable))
        {
            std::string s = string(attribute_tag(tag));
            // Break this string into keywords and add it to our list
            auto words_begin = sregex_iterator(s.begin(), s.end(), word_regex);
            auto words_end = sregex_iterator();

            const int N = 2;
            for (sregex_iterator i = words_begin; i != words_end; ++i) {
                smatch match = *i;
                std::string match_str = match.str();
                if (match_str.size() >= N) {
                    result.emplace_back(match_str);
                }
            }
        }
    }
    return result;
}

vector<uia::comm::endpoint>
client_profile::endpoints() const
{
    vector<uia::comm::endpoint> result;
    {
        byte_array_iwrap<flurry::iarchive> read(attribute(attribute_tag::endpoints));
        read.archive() >> result;
    }
    return result;
}

void
client_profile::set_endpoints(vector<uia::comm::endpoint> const& endpoints)
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
