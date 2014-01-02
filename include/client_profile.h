//
// Part of Metta OS. Check http://metta.exquance.com for latest version.
//
// Copyright 2007 - 2014, Stanislav Karchebnyy <berkus@exquance.com>
//
// Distributed under the Boost Software License, Version 1.0.
// (See file LICENSE_1_0.txt or a copy at http://www.boost.org/LICENSE_1_0.txt)
//
#pragma once

#include <boost/range/adaptor/map.hpp>
#include <boost/range/algorithm/copy.hpp>
#include "byte_array.h"
#include "byte_array_wrap.h"
#include "link.h"
#include "underlying.h"

namespace uia {
namespace routing {

// Client profile represents a client-specified block of information
// about itself to be made publicly available to other clients
// through a registration server.
class client_profile
{
public:
    // Attribute tags - will grow over time.
    // The upper 16 bits are for attribute property flags.
    enum class attribute_tag : uint32_t
    {
        invalid     = 0x00000000,   ///< Invalid attribute

        // Flags indicating useful properties of certain tags
        searchable  = 0x00010000,   ///< Search-worthy text (UTF-8)

        // Specific binary tags useful for rendezvous
        endpoints   = 0x00000001,   ///< Private addresses for hole punch

        // UTF-8 string tags representing advertised information
        // this is fairly preliminary at the moment.
        hostname        = 0x00010001,  ///< Name of host (machine)
        owner_nickname  = 0x00010002,  ///< Name of owner (human)
        city            = 0x00010003,  ///< Metropolitan area
        region          = 0x00010004,  ///< State or other locality
        country         = 0x00010005,  ///< Political state
        owner_firstname = 0x00010006,  ///< Owner real first name
        owner_lastname  = 0x00010007,  ///< Owner real last name
    };

    // Constructors
    inline client_profile() = default;
    inline client_profile(client_profile const& other) = default;
    inline client_profile(byte_array const& data) { deflurry(data); }

    inline client_profile& operator =(client_profile const& other) = default;
    inline client_profile& operator =(client_profile&& other) = default;

    /** @name Basic attribute management methods. */
    /**@{*/
    inline bool is_empty() const { return attributes_.empty(); }

    inline std::vector<std::underlying_type<attribute_tag>::type>
    tags() const {
        std::vector<std::underlying_type<attribute_tag>::type> keys;
        boost::copy(attributes_ | boost::adaptors::map_keys, std::back_inserter(keys));
        return keys;
    }

    inline byte_array attribute(attribute_tag tag) const {
        if (!contains(attributes_, to_underlying(tag))) {
            return byte_array();
        }
        return attributes_.at(to_underlying(tag));
    }
    inline void set_attribute(attribute_tag tag, byte_array const& value) {
        attributes_[to_underlying(tag)] = value;
    }
    inline void remove(attribute_tag tag) {
        set_attribute(tag, byte_array());
    }

    /**@}*/

    /** @name String attribute get/set. */
    /**@{*/
    inline std::string string(attribute_tag tag) const {
        byte_array data = attribute(tag);
        return std::string(data.begin(), data.end());
    }
    inline void set_string(attribute_tag tag, std::string const& value) {
        set_attribute(tag, byte_array::wrap(value.c_str(), value.size()));
    }
    /**@}*/

    /** @name Type-specific methods for individual attributes. */
    /**@{*/
    inline std::string host_name()  const { return string(attribute_tag::hostname); }
    inline std::string owner_nickname() const { return string(attribute_tag::owner_nickname); }
    inline std::string owner_firstname() const { return string(attribute_tag::owner_firstname); }
    inline std::string owner_lastname() const { return string(attribute_tag::owner_lastname); }
    inline std::string city()       const { return string(attribute_tag::city); }
    inline std::string region()     const { return string(attribute_tag::region); }
    inline std::string country()    const { return string(attribute_tag::country); }

    inline void set_host_name(std::string const& str) {
        set_string(attribute_tag::hostname, str);
    }
    inline void set_owner_nickname(std::string const& str) {
        set_string(attribute_tag::owner_nickname, str);
    }
    inline void set_owner_firstname(std::string const& str) {
        set_string(attribute_tag::owner_firstname, str);
    }
    inline void set_owner_lastname(std::string const& str) {
        set_string(attribute_tag::owner_lastname, str);
    }
    inline void set_city(std::string const& str) {
        set_string(attribute_tag::city, str);
    }
    inline void set_region(std::string const& str) {
        set_string(attribute_tag::region, str);
    }
    inline void set_country(std::string const& str) {
        set_string(attribute_tag::country, str);
    }
    /**@}*/

    /**
     * Return all the words appearing in all searchable string attributes.
     */
    std::vector<std::string> keywords() const;

    /** @name Advertised private endpoints. */
    /**@{*/
    std::vector<ssu::endpoint> endpoints() const;
    void set_endpoints(std::vector<ssu::endpoint> const& endpoints);
    /**@}*/

    inline void enflurry(flurry::oarchive& oa) const {
        oa << attributes_;
    }
    inline byte_array enflurry() const {
        byte_array out;
        {
            byte_array_owrap<flurry::oarchive> write(out);
            write.archive() << attributes_;
        }
        return out;
    }
    inline void deflurry(flurry::iarchive& ia) {
        attributes_.clear();
        ia >> attributes_;
    }
    inline void deflurry(byte_array const& data) {
        attributes_.clear();
        byte_array_iwrap<flurry::iarchive> read(data);
        read.archive() >> attributes_;
    }    
private:
    std::unordered_map<std::underlying_type<attribute_tag>::type, byte_array> attributes_;
};

inline flurry::oarchive& operator << (flurry::oarchive& oa, client_profile const& cp)
{
    cp.enflurry(oa);
    return oa;
}

inline flurry::iarchive& operator >> (flurry::iarchive& ia, client_profile& cp)
{
    cp.deflurry(ia);
    return ia;
}

} // routing namespace
} // uia namespace
