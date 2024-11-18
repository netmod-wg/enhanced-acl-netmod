---
title: Extensions to the Access Control Lists (ACLs) YANG Model
abbrev: Enhanced ACLs
docname: draft-ietf-netmod-acl-extensions-latest


stand_alone: true
ipr: trust200902
area: "Operations and Management"
wg: netmod
kw: Internet-Draft
cat: std
submissiontype: IETF

coding: utf-8
pi: [toc, sortrefs, symrefs]

author:
 -
    fullname: Oscar Gonzalez de Dios
    organization: Telefonica
    email: oscar.gonzalezdedios@telefonica.com
 -
    fullname: Samier Barguil
    organization: Nokia
    email: samier.barguil_giraldo@nokia.com
 -
    fullname: Mohamed Boucadair
    organization: Orange
    email: mohamed.boucadair@orange.com
 -
    fullname: Qin Wu
    organization: Huawei
    email: bill.wu@huawei.com

informative:
   IANA-YANG-PARAMETERS:
              title: "YANG Parameters"
              target: https://www.iana.org/assignments/yang-parameters

   IANA-TCP-FLAGS:
              title: "Transmission Control Protocol (TCP) Parameters"
              target: https://www.iana.org/assignments/tcp-parameters/

   IANA-ICMPv4:
              title: "ICMP Type Numbers"
              target: https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml

   IANA-ICMPv6:
              title: "ICMPv6 type Numbers"
              target: https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml

   IANA-IPv6:
              title: "IPv6 Extension Header Types"
              target: https://www.iana.org/assignments/ipv6-parameters/ipv6-parameters.xhtml

   IANA_ICMPv4_YANG_URL:
              title: "iana-icmpv6-types YANG Module"
              target: https://www.iana.org/assignments/icmpv6-parameters/iana-icmpv6-types.xhtml

   IANA_ICMPv6_YANG_URL:
              title: "iana-icmpv4-types YANG Module"
              target: https://www.iana.org/assignments/icmp-parameters/iana-ipv6-ext-types.xhtml

   IANA_IPV6_YANG_URL:
              title: "iana-ipv6-ext-types YANG Module"
              target: https://www.iana.org/assignments/ipv6-parameters/iana-icmpv6-types.xhtml

   IEEE-802-1ah:
              title: "IEEE Standard for Local and metropolitan area networks -- Virtual Bridged Local Area Networks Amendment 7: Provider Backbone Bridges"
              date: August 2008
              target: https://standards.ieee.org/standard/802_1ah-2008.html
              author:
              -
                name: IEEE

   IEEE802.1Qcp:
              title: "IEEE Standard for Local and metropolitan area networks--Bridges and Bridged Networks--Amendment 30: YANG Data Model"
              date: September 2018
              target: https://doi.org/10.1109/IEEESTD.2018.8467507
              author:
              -
                name: IEEE

--- abstract

RFC 8519 defines a YANG data model for Access Control Lists
(ACLs). This document discusses a set of extensions that fix many of
the limitations of the ACL model as initially defined in RFC 8519.

The document also defines IANA-maintained modules for ICMP types and IPv6 extension headers.

--- middle

# Introduction

{{!RFC8519}} defines Access Control Lists (ACLs) as a
user-ordered set of filtering rules. The model targets the
configuration of the filtering behavior of a device. However, the
model structure, as defined in {{!RFC8519}}, suffers from a set of limitations. This
document describes these limitations and specifies an enhanced ACL
structure ({{sec-module}}). The motivation of such enhanced ACL structure is discussed in detail in {{ps}}.

When managing ACLs, it is common for network operators to group
match elements in pre-defined sets. The consolidation into group matches
allows for reducing the number of rules, especially in large scale
networks. If, for example, it is needed to find a match against 100
IP addresses (or prefixes), a single rule will suffice rather than creating
individual Access Control Entries (ACEs) for each IP address (or prefix). In
doing so, implementations would optimize the performance of matching
lists vs multiple rules matching.

The enhanced ACL structure ({{sec-module}}) is also meant to facilitate the management of
network operators. Instead of entering the IP address or port number
literals, using user-named lists decouples the creation of the rule
from the management of the sets. Hence, it is possible to remove/add
 entries to the list without redefining the (parent) ACL rule.

In addition, the notion of Access Control List (ACL) and defined sets
is generalized so that it is not device-specific as per {{!RFC8519}}.  ACLs
and defined sets may be defined at network/administrative domain level
and associated to devices. This approach facilitates the reusability across multiple
network elements. For example, managing the IP prefix sets from a network
level makes it easier to maintain by the security groups.

Network operators maintain sets of IP prefixes that are related to each other,
e.g., deny-lists or accept-lists that are associated with those provided by a
 VPN customer. These lists are maintained and manipulated by security expert teams.

Note that ACLs are used locally in devices but are triggered by other
tools such as DDoS mitigation {{?RFC9132}} or BGP Flow Spec {{?RFC8955}}
{{!RFC8956}}. Therefore, supporting means to easily map to the filtering rules conveyed in
messages triggered by  these tools is valuable from a network operation standpoint.

The enhanced ACL module ({{sec-module}}) conforms to the Network
Management Datastore Architecture (NMDA) defined in {{!RFC8342}}.

A set of examples to illustrate the use of the enhanced ACL module are provided in {{sec-examples}}.

The document also defines IANA-maintained modules for ICMP types and IPv6 extension headers. The design of the modules adheres to the recommendations
in {{?I-D.ietf-netmod-rfc8407bis}}. The templates to generate the modules are available in {{template}}, {{v6-template}}, and {{iana-ipv6-ext-template}}. Readers should refer to the IANA websites {{IANA_ICMPv4_YANG_URL}}, {{IANA_ICMPv6_YANG_URL}}, and {{IANA_IPV6_YANG_URL}} to retrieve the latest version of these IANA-maintained modules.

## Editorial Note (To be removed by RFC Editor)

Note to the RFC Editor: This section is to be removed prior to publication.

This document contains placeholder values that need to be replaced with finalized values at the time of publication. This note summarizes all of the substitutions that are needed.

(1) Please apply the following replacements:

  * XXXX --> the assigned RFC number for this I-D
  * 2024-05-16 --> the actual date of the publication of this document

(2) The modules are provided in {{iana-icmp}}, {{iana-icmpv6}}, and {{iana-ipv6-ext}} for the users convenience before publication as RFC. Please remove these appendices from the final RFC.

(3) Please update  the following references:

   * IANA_ICMPv4_YANG_URL --> The URL to retrieve the latest version of the IANA-maintained ICMPv4 module.
   * IANA_ICMPv6_YANG_URL --> The URL to retrieve the latest version of the IANA-maintained ICMPv6 module.
   * IANA_IPV6_YANG_URL --> The URL to retrieve the latest version of the IPv6 Extension Header Types IANA module.

# Terminology

{::boilerplate bcp14-tagged}

The terminology for describing YANG modules is defined in {{!RFC7950}}.
The meaning of the symbols in the tree diagrams is defined in
{{?RFC8340}}.

In addition to the terms defined in {{!RFC8519}}, this document makes use of the following term:

Defined set:
: Refers to reusable description of one or multiple information elements (e.g., IP address, IP prefix, port number, or ICMP type).

# Overall Structure of The Enhanced ACL Module

## Tree Structure

{{enh-acl-tree}} shows the full tree of the enhanced ACL module ({{sec-module}}):

~~~
{::include-fold ./yang/enh-tree.txt}
~~~
{: #enh-acl-tree title="Enhanced ACL Tree Structure"}

{{enh-acl-grp}} shows the reusable groupings that are defined in the enhanced ACL module:

~~~
{::include-fold  ./yang/groupings.txt}
~~~
{: #enh-acl-grp title="Enhanced ACL Groupings"}

## Defined Sets

The augmented ACL structure includes several containers to manage reusable sets of elements that can be matched in an ACL entry.
Each set is uniquely identified by a name and can be called from the relevant entry. The following sets are defined ({{enh-acl-tree}}):

IPv4 prefix sets:
: An IPv4 prefix set contains a list of IPv4 prefixes. A match will be considered if the IP address (source or destination, depending on the ACL entry) is contained in any of the prefixes in the set.

IPv6 prefix sets:
: An IPv6 prefix contains a list of IPv6 prefixes. A match will be considered if the IP address (source or destination, depending on the ACL entry) is contained in any of the prefixes in the set.

Port sets:
: A port set contains a list of port numbers to be used in transpot protocol entries (e.g., TCP and UDP).
: The port numbers can be individual port numbers, a range of port numbers, and an operation.

Protocol sets:
: A protocol set contains a list of protocol values. Each protocol can be identified either by a number (e.g., 17) or a name (e.g., UDP).

ICMP sets:
: An ICMP set contains a list of ICMPv4 {{!RFC0792}} or ICMPv6 {{!RFC4443}} types, each of them identified by a type value, optionally the code and the rest of the header.
: New IANA-maintained modules for ICMP types are defined in this document.

Aliases:
: An alias is defined by a combination of various parameters (e.g., IP prefix, protocol, port number, or VLAN {{IEEE802.1Qcp}}). Sets of aliases can be defined and referred to in ACL match criteria.

## IPv6 Extension Headers

The module can be used to manage ACLs that require matching against IPv6 extension headers {{!RFC8200}}. To that aim, a new IANA-maintained module for IPv6 extension header types "iana-ipv6-ext-types" is defined in this document.

## TCP Flags Handling

The augmented ACL structure ({{enh-acl-tree}}) includes a new container 'flags-bitmask' to better handle TCP flags ({{Section 3.1 of !RFC9293}}). Assigned TCP flags are maintained in the "TCP Header Flags" registry under the "Transmission Control Protocol (TCP) Parameters" registry group {{IANA-TCP-FLAGS}}.

Clients that support both 'flags-bitmask' and 'flags' {{!RFC8519}} matching fields MUST NOT set these fields in the same request.

## Fragments Handling

The augmented ACL structure ({{enh-acl-tree}}) includes new leafs 'ipv4-fragment' and 'ipv6-fragment' to better handle fragments.

Clients that support both 'ipv4-fragment' and 'flags' {{!RFC8519}} matching fields MUST NOT set these fields in the same request.

## Payload-based Filtering

Some transport protocols use existing protocols (e.g., TCP or UDP) as substrate. The match criteria for such protocols may rely upon the 'protocol' under 'l3', TCP/UDP match criteria, part of the TCP/UDP payload, or a combination thereof.

A new feature, called 'match-on-payload', is defined in the document. This can be used, for example, for QUIC {{?RFC9000}} or for tunneling protocols.

## Match on MPLS Headers

The enhanced ACL module ({{sec-module}}) can be used to create rules to match against MPLS fields of a packet. The MPLS header defined in {{!RFC3032}} and {{!RFC5462}} contains the following fields:

- Traffic Class: The 3-bit "Exp" field {{!RFC3032}} which is renamed to "Traffic Class field" ("TC field") {{!RFC5462}}.
- Label Value: A 20-bit field that carries the actual value of the MPLS label.
- TTL: A 8-bit field used to encode Time to Live (TTL) value.

The augmented ACL structure ({{enh-acl-tree}}) allows an operator to configure ACLs that match based upon the following data nodes:

* 'traffic-class'
* 'label-position' (e.g., top or bottom)
* 'upper-label-range'
* 'lower-label-range'
* 'label-block-name'
* 'ttl-value'

## VLAN Filtering

Being able to filter all packets that are bridged within a VLAN or that
are routed into or out of a bridge domain is part of the VPN control
requirements for Ethernet VPN (EVPN) {{?RFC7209}}.
All packets that are bridged within a VLAN or that are routed into or
out of a VLAN can be captured, forwarded, translated, or discarded based
on the network policy.

## Instance Service Identifier (I-SID) Filtering

Provider backbone bridging (PBB) was originally defined as Virtual
Bridged Local Area Networks {{IEEE-802-1ah}}
standard. However, instead of multiplexing VLANs, PBB
duplicates the MAC layer of the customer frame and separates it from
the provider domain, by encapsulating it in a 24-bit instance service
identifier (I-SID). This provides more transparency between the
customer network and the provider network.

The I-component forms the customer or access facing interface or
routing instance. The I-component is responsible for mapping customer
Ethernet traffic to the appropriate I-SID. It is
mandatory to configure the default service identifier in the network.

Being able to filter by I-component Service identifier is a feature of
the EVNP-PBB configuration.

## Additional Actions

In order to support rate-limiting (see {{ps-rate}}), a new action called 'rate-limit' is defined in this document. Also, the "ietf-acl-enh" module supports new actions to complement existing ones: Log ('log-action') and write a counter ('counter-action'). The version of the module defined in this document supports only local actions.

# Enhanced ACL YANG Module {#sec-module}

This model imports types from {{!RFC6991}}, {{!RFC8519}}, and {{!RFC8294}}.

~~~
<CODE BEGINS> file "ietf-acl-enh@2024-05-16.yang"
{::include-fold ./yang/ietf-acl-enh.yang}
<CODE ENDS>
~~~

# Security Considerations

This section is modeled after the template described in {{Section 3.7 of ?I-D.ietf-netmod-rfc8407bis}}.

The "ietf-acl-enh" YANG module defines a data model that is
designed to be accessed via YANG-based management protocols, such as
NETCONF {{?RFC6241}} and RESTCONF {{?RFC8040}}. These protocols have to
use a secure transport layer (e.g., SSH {{?RFC4252}}, TLS {{?RFC8446}}, and
QUIC {{?RFC9000}}) and have to use mutual authentication.

The Network Configuration Access Control Model (NACM) {{!RFC8341}} provides the means to restrict access for particular NETCONF or RESTCONF users to a preconfigured subset of all available NETCONF or RESTCONF protocol operations and content.

There are a number of data nodes defined in the "ietf-acl-enh" YANG module that are writable/creatable/deletable (i.e., config true, which is the default). These data nodes may be considered sensitive or vulnerable in some network environments. Write operations (e.g., edit-config) to these data nodes without proper protection can have a negative effect on network operations. These are the subtrees and data nodes and their sensitivity/vulnerability:

 'defined-sets':
 : These lists specify a set of sets and aliases. Similar to {{!RFC8519}}, unauthorized write access to these
      list can allow intruders to modify the entries so as to permit
      traffic that should not be permitted, or deny traffic that should
      be permitted.  The former may result in a DoS attack, or
      compromise a device.  The latter may result in a DoS attack.

Some of the readable data nodes in the "ietf-acl-enh" YANG module may be considered sensitive or vulnerable in some network environments. It is thus important to control read access (e.g., via get, get-config, or notification) to these data nodes. These are the subtrees and data nodes and their sensitivity/vulnerability:

 'defined-sets':
 : Unauthorized read access of these lists will allow
   an attacker to identify the actual resources that are bound
   to ACLs.

The document defines a match policy based on a pattern that can be observed in a packet. For example, such a policy can be combined with header-based matches in the context of DDoS mitigation. Filtering based on a pattern match is deterministic for packets with unencrypted data. However, the efficiency for encrypted
packets depend on the presence of an unvarying pattern.

The YANG modules "iana-icmpv4-types", "iana-icmpv6-types", and "iana-ipv6-ext-types defines" a set of types. These nodes are intended to be reused by other YANG
modules. Each of these modules by itself does not expose any data nodes that
are writable, data nodes that contain read-only state, or RPCs.
As such, there are no additional security issues related to
these YANG modules that need to be considered.

# IANA Considerations

## URI Registrations

   This document requests IANA to register the following URIs in the "ns"
   subregistry within the "IETF XML Registry" {{!RFC3688}}:

~~~
URI: urn:ietf:params:xml:ns:yang:ietf-acl-enh
Registrant Contact: The IESG.
XML: N/A; the requested URI is an XML namespace.

URI: urn:ietf:params:xml:ns:yang:iana-icmpv4-types
Registrant Contact: The IESG.
XML: N/A; the requested URI is an XML namespace.

URI: urn:ietf:params:xml:ns:yang:iana-icmpv6-types
Registrant Contact: The IESG.
XML: N/A; the requested URI is an XML namespace.

URI: urn:ietf:params:xml:ns:yang:iana-ipv6-ext-types
Registrant Contact: The IESG.
XML: N/A; the requested URI is an XML namespace.
~~~

## YANG Module Name Registrations

This document requests IANA to register the following YANG modules in
   the "YANG Module Names" subregistry {{!RFC6020}} within the "YANG
   Parameters" registry.

~~~
name: ietf-acl-enh
namespace: urn:ietf:params:xml:ns:yang:ietf-acl-enh
maintained by IANA: N
prefix: acl-enh
reference: RFC XXXX

name: iana-icmpv4-types
namespace: urn:ietf:params:xml:ns:yang:iana-icmpv4-types
maintained by IANA: Y
prefix: iana-icmpv4-types
reference: RFC XXXX

name: iana-icmpv6-types
namespace: urn:ietf:params:xml:ns:yang:iana-icmpv6-types
maintained by IANA: Y
prefix: iana-icmpv6-types
reference: RFC XXXX

name: iana-ipv6-ext-types
namespace: urn:ietf:params:xml:ns:yang:iana-ipv6-ext-types
maintained by IANA: Y
prefix: iana-ipv6-ext-types
reference: RFC XXXX
~~~

## Considerations for IANA-Maintained Modules

### ICMPv4 Types IANA Module

IANA is requested to create and post
the initial version of the "iana-icmpv4-types" YANG module by
applying the XSLT stylesheet from {{template}} to the XML version of
{{IANA-ICMPv4}}.

This document defines the initial version of the IANA-maintained
"iana-icmpv4-types" YANG module.  The most recent version of the YANG module
is available from the "YANG Parameters" registry
{{IANA-YANG-PARAMETERS}}.

IANA is requested to add this note to the registry {{IANA-YANG-PARAMETERS}}:

> New values must not be directly added to the "iana-icmpv4-types" YANG module.  They must instead be added to the "ICMP Type Numbers" registry {{IANA-ICMPv4}}.

When a value is added to the "ICMP Type Numbers" registry, a new "enum" statement
must be added to the "iana-icmpv4-types" YANG module.  The "enum" statement,
and sub-statements thereof, should be defined:

"enum":
: Replicates the name from the registry with all spaces striped.

"value":
: Contains the decimal value of the IANA-assigned value.

"status":
:      Is included only if a registration has been deprecated
       or obsoleted.  IANA "deprecated" maps to YANG status
       "deprecated", and IANA "obsolete" maps to YANG status
       "obsolete".

"description":
: Replicates the name from the registry.

"reference":
:   Replicates the reference(s) from the registry with the
    title of the document(s) added.

Unassigned or reserved values are not present in the module.

When the "iana-icmpv4-types" YANG module is updated, a new "revision"
statement with a unique revision date must be added in front of the
existing revision statements.

IANA is requested to add this note to "ICMP Type Numbers" {{IANA-ICMPv4}}:

    When this registry is modified, the YANG module "iana-icmpv4-types"
    [IANA_ICMPv4_YANG_URL] must be updated as defined in RFC XXXX.

IANA is requested to updated the "Reference" in the "ICMP Type Numbers" registry
as follows:

OLD:
: {{?RFC2780}}

NEW:
: {{?RFC2780}}[RFCXXXX]

### ICMPv6 Types IANA Module

IANA is requested to create and post
the initial version of the "iana-icmpv6-types" YANG module by
applying the XSLT stylesheet from {{v6-template}} to the XML version of
{{IANA-ICMPv4}}.

This document defines the initial version of the IANA-maintained
"iana-icmpv6-types" YANG module.  The most recent version of the YANG module
is available from the "YANG Parameters" registry
{{IANA-YANG-PARAMETERS}}.

IANA is requested to add this note to the registry {{IANA-YANG-PARAMETERS}}:

> New values must not be directly added to the "iana-icmpv6-types" YANG module. They must instead be added to the "ICMPv6 "type" Numbers" registry {{IANA-ICMPv6}}.

When a value is added to the "ICMPv6 "type" Numbers" registry, a new "enum" statement
must be added to the "iana-icmpv6-types" YANG module.  The "enum" statement,
and sub-statements thereof, should be defined:

"enum":
: Replicates the name from the registry with all spaces striped.

"value":
: Contains the decimal value of the IANA-assigned value.

"status":
:      Is included only if a registration has been deprecated
       or obsoleted.  IANA "deprecated" maps to YANG status
       "deprecated", and IANA "obsolete" maps to YANG status
       "obsolete".

"description":
: Replicates the name from the registry.

"reference":
:   Replicates the reference(s) from the registry with the
    title of the document(s) added.

Unassigned or reserved values are not present in the module.

When the "iana-icmpv6-types" YANG module is updated, a new "revision"
statement with a unique revision date must be added in front of the
existing revision statements.

IANA is requested to add this note to "ICMPv6 "type" Numbers" {{IANA-ICMPv6}}:

    When this registry is modified, the YANG module "iana-icmpv6-types"
    [IANA_ICMPv6_YANG_URL] must be updated as defined in RFC XXXX.

IANA is requested to updated the "Reference" in the "ICMPv6 "type" Numbers" registry
as follows:

OLD:
: {{?RFC4443}}

NEW:
: {{?RFC4443}}[RFCXXXX]

### IPv6 Extension Header Types IANA Module

IANA is requested to create and post
the initial version of the "iana-ipv6-ext-types" YANG module by
applying the XSLT stylesheet from {{iana-ipv6-ext-template}} to the XML version of
{{IANA-IPv6}}.

This document defines the initial version of the IANA-maintained
"iana-ipv6-ext-types" YANG module.  The most recent version of the YANG module
is available from the "YANG Parameters" registry
{{IANA-YANG-PARAMETERS}}.

IANA is requested to add this note to the registry {{IANA-YANG-PARAMETERS}}:

> New values must not be directly added to the "iana-ipv6-ext-types" YANG module.  They must instead be added to the "IPv6 Extension Header Types" registry {{IANA-ICMPv6}}.

When a value is added to the "IPv6 Extension Header Types" registry, a new "enum" statement
must be added to the "iana-ipv6-ext-types" YANG module.  The "enum" statement,
and sub-statements thereof, should be defined:

"enum":
: Replicates the description from the registry with all spaces striped.

"value":
: Contains the decimal value of the IANA-assigned value.

"status":
:      Is included only if a registration has been deprecated
       or obsoleted.  IANA "deprecated" maps to YANG status
       "deprecated", and IANA "obsolete" maps to YANG status
       "obsolete".

"description":
: Replicates the description from the registry.

"reference":
:   Replicates the reference(s) from the registry with the
    title of the document(s) added.

Unassigned or reserved values are not present in the module.

When the "iana-ipv6-ext-types" YANG module is updated, a new "revision"
statement with a unique revision date must be added in front of the
existing revision statements.

IANA is requested to add this note to the "IPv6 Extension Header Types" registry {{IANA-IPv6}}:

    When this registry is modified, the YANG module "iana-ipv6-ext-types"
    [IANA_IPV6_YANG_URL] must be updated as defined in RFC XXXX.

IANA is requested to updated the "Reference" in the "IPv6 Extension Header Types" registry
as follows:

OLD:
: {{?RFC2780}}{{?RFC5237}}{{?RFC7045}}

NEW:
: {{?RFC2780}}{{?RFC5237}}{{?RFC7045}}[RFCXXXX]


--- back

# ICMPv4 Types

## XSLT Template to Generate The ICMPv4 Types IANA-Maintained Module {#template}

~~~
<CODE BEGINS>

{::include-fold ./yang/iana-icmpv4-types.xsl}

<CODE ENDS>
~~~

## Initial Version of the ICMPv4 Types IANA-Maintained Module {#iana-icmp}

~~~
<CODE BEGINS> file "iana-icmpv4-types@2020-09-25.yang"

{::include-fold ./yang/iana-icmpv4-types.yang}

<CODE ENDS>
~~~

# ICMPv6 Types

## XSLT Template to Generate the ICMPv6 Types IANA-Maintained Module {#v6-template}

~~~
<CODE BEGINS>

{::include-fold ./yang/iana-icmpv6-types.xsl}

<CODE ENDS>
~~~

## Initial Version of the ICMPv6 Types IANA-Maintained Module {#iana-icmpv6}

~~~
<CODE BEGINS> file "iana-icmpv6-types@2023-04-28.yang"

{::include-fold ./yang/iana-icmpv6-types.yang}

<CODE ENDS>
~~~

# IPv6 Extension Header Types

## XSLT Template to Generate The IPv6 Extension Header Types IANA-Maintained Module {#iana-ipv6-ext-template}

~~~
<CODE BEGINS>

{::include-fold ./yang/iana-ipv6-ext-types.xsl}

<CODE ENDS>
~~~

## Initial Version of The IPv6 Extension Header Types IANA-Maintained Module {#iana-ipv6-ext}

~~~
<CODE BEGINS> file "iana-ipv6-ext-types@2023-09-29.yang"

{::include-fold ./yang/iana-ipv6-ext-types.yang}

<CODE ENDS>
~~~

# Problem Statement & Gap Analysis {#ps}

## Suboptimal Configuration: Lack of Support for Lists of Prefixes {#ps-sets}

IP prefix-related data nodes, e.g., "destination-ipv4-network" or
   "destination-ipv6-network", do not support handling a list of IP
   prefixes, which may then lead to having to support large numbers of ACL entries in a configuration file.

The same issue is encountered when ACLs have to be in place to mitigate DDoS
attacks that involve a set of sources (e.g., {{?RFC9132}}). The situation is even worse when both a list of sources
and destination prefixes are involved in the filtering.

{{example}} shows an example of the required ACL configuration for filtering traffic from two prefixes.

~~~~~~~~~~~
{
  "ietf-access-control-list:acls": {
    "acl": [
      {
        "name": "first-prefix",
        "type": "ipv6-acl-type",
        "aces": {
          "ace": [
            {
              "name": "my-test-ace",
              "matches": {
                "ipv6": {
                  "destination-ipv6-network":
                    "2001:db8:6401:1::/64",
                  "source-ipv6-network":
                    "2001:db8:1234::/96",
                  "protocol": 17,
                  "flow-label": 10000
                },
                "udp": {
                  "source-port": {
                    "operator": "lte",
                    "port": 80
                  },
                  "destination-port": {
                    "operator": "neq",
                    "port": 1010
                  }
                }
              },
              "actions": {
                "forwarding": "accept"
              }
            }
          ]
        }
      },
      {
        "name": "second-prefix",
        "type": "ipv6-acl-type",
        "aces": {
          "ace": [
            {
              "name": "my-test-ace",
              "matches": {
                "ipv6": {
                  "destination-ipv6-network":
                    "2001:db8:6401:c::/64",
                  "source-ipv6-network":
                    "2001:db8:1234::/96",
                  "protocol": 17,
                  "flow-label": 10000
                },
                "udp": {
                  "source-port": {
                    "operator": "lte",
                    "port": 80
                  },
                  "destination-port": {
                    "operator": "neq",
                    "port": 1010
                  }
                }
              },
              "actions": {
                "forwarding": "accept"
              }
            }
          ]
        }
      }
    ]
  }
}
~~~~~~~~~~~
{: #example title="Example Illustrating Sub-optimal Use of the ACL Model with a Prefix List (Message Body)"}

Such a configuration is suboptimal for both:

- Network controllers that need to manipulate large files. All or a
  subset for this configuration will need to be passed to the
  underlying network devices.
- Devices may receive such a configuration and thus will need to
  maintain it locally.

## Manageability: Impossibility to Use Aliases or Defined Sets

The same approach as the one discussed for IP prefixes can be generalized by introducing the concept of "aliases" or "defined sets".

The defined sets are reusable definitions across several ACLs. Each category is modeled in YANG as a list of parameters related to the class it represents. The following sets can be considered:

Prefix sets:
: Used to create lists of IPv4 or IPv6 prefixes.

Protocol sets:
: Used to create a list of protocols.

Port number sets:
:  Used to create lists of TCP or UDP port values
      (or any other transport protocol that makes uses of port numbers).
      The identity of the protocols is identified by the protocol set, if
      present.  Otherwise, a set applies to any protocol.

ICMP sets:
: Uses to create lists of ICMP-based filters. This applies only when the protocol is set to ICMP or ICMPv6.

Aliases may also be considered to manage resources that are identified by a combination of various parameters (e.g., prefix, protocol, port number, FQDN, or VLAN IDs).
Note that some aliases can be provided by decomposing them into separate sets.

## Bind ACLs to Devices, Not Only Interfaces

In the context of network management, an ACL may be enforced in many
   network locations.  As such, the ACL module should allow for binding an
   ACL to multiple devices, not only (abstract) interfaces.

The ACL name must, thus, be unique at the scale of the network, but the same name may be used in many devices when enforcing node-specific ACLs.

## Partial or Lack of IPv4/IPv6 Fragment Handling {#ps-frag}

{{!RFC8519}} does not support fragment handling for IPv6 but
offers a partial support for IPv4  through the use of 'flags'.  Nevertheless,
the use of 'flags' is problematic since it does not allow a bitmask
to be defined.  For example, setting other bits not covered by the
'flags' filtering clause in a packet will allow that packet to get
through (because it won't match the ACE).

Defining a new IPv4/IPv6 matching field called 'fragment' is thus required to efficiently handle fragment-related filtering rules.

## Suboptimal TCP Flags Handling {#ps-flags}

{{!RFC8519}} supports including flags in the TCP match fields, however
   that structure does not support matching operations as those
   supported in BGP Flow Spec.  Defining this field to be defined as a
   flag bitmask together with a set of operations is meant to
   efficiently handle TCP flags filtering rules.


## Rate-Limit Action {#ps-rate}

 {{!RFC8519}} specifies that forwarding actions can be 'accept' (i.e., accept matching
   traffic), 'drop' (i.e., drop matching traffic without sending any
   ICMP error message), or 'reject' (i.e., drop matching traffic and send an ICMP error message to the source). However, there are situations where the matching traffic can be accepted, but with a rate-limit policy. This capability is not supported by {{!RFC8519}}.

## Payload-based Filtering {#ps-pf}

Some transport protocols use existing protocols (e.g., TCP or UDP) as substrate. The match criteria for such protocols may rely upon the 'protocol' under 'l3', TCP/UDP match criteria, part of the TCP/UDP payload, or a combination thereof. {{!RFC8519}} does not support matching based on the payload.

Likewise, the current version of the ACL model does not support filtering of encapsulated traffic.

## Reuse the ACLs Content Across Several Devices

Having a global network view of the ACLs is highly valuable for service providers. An ACL could be defined and applied
based on the network topology hierarchy. So, an ACL can be
defined at the network level and, then, that same ACL can be used (or referenced to)
in several devices (including termination points) within the same network.

This network/device ACLs differentiation introduces several new
requirements, e.g.:

* An ACL name can be used at both network and device levels.
* An ACL content updated at the network level should imply
  a transaction that updates the relevant content in all the nodes using this
  ACL.
* ACLs defined at the device level have a local meaning for the specific node.
* A device can be associated with a router, a VRF, a
  logical system, or a virtual node. ACLs can be applied in physical and
  logical infrastructure.

## Match MPLS Headers

The ACLs could be used to create rules to match MPLS fields on a packet. {{!RFC8519}} does not support such function.

# Examples {#sec-examples}

This section provides a few examples to illustrate the use of the enhanced ACL module ("ietf-acl-enh").

## TCP Flags Handling

{{example_4}} shows an example of the message body of a request to install a filter to discard incoming TCP messages having all flags unset.

~~~ json
{
  "ietf-access-control-list:acls": {
    "acl": [
      {
        "name": "tcp-flags-example",
        "aces": {
          "ace": [
            {
              "name": "null-attack",
              "matches": {
                "tcp": {
                  "ietf-acl-enh:flags-bitmask": {
                    "operator": "not any",
                    "bitmask": 4095
                  }
                }
              },
              "actions": {
                "forwarding": "drop"
              }
            }
          ]
        }
      }
    ]
  }
}
~~~
{: #example_4 title="Example of an ACL to Deny TCP Null Attack Messages (Request Body)"}

## Fragments Handling

{{example_2}} shows the content of a POST request to allow the traffic destined to 198.51.100.0/24 and UDP port number 53, but to drop all fragmented
packets.  The following ACEs are defined (in this order):

* "drop-all-fragments" ACE: discards all fragments.
* "allow-dns-packets" ACE: accepts DNS packets destined to 198.51.100.0/24.

~~~ json
{
  "ietf-access-control-list:acls": {
    "acl": [
      {
        "name": "dns-fragments",
        "type": "ipv4-acl-type",
        "aces": {
          "ace": [
            {
              "name": "drop-all-fragments",
              "matches": {
                "ipv4": {
                  "ietf-acl-enh:ipv4-fragment": {
                    "operator": "match",
                    "type": "isf"
                  }
                }
              },
              "actions": {
                "forwarding": "drop"
              }
            },
            {
              "name": "allow-dns-packets",
              "matches": {
                "ipv4": {
                  "destination-ipv4-network": "198.51.100.0/24"
                },
                "udp": {
                  "destination-port": {
                    "operator": "eq",
                    "port": 53
                  }
                }
              },
              "actions": {
                "forwarding": "accept"
              }
            }
          ]
        }
      }
    ]
  }
}
~~~
{: #example_2 title="Example Illustrating Candidate Filtering of IPv4 Fragmented Packets (Message Body)"}

{{example_3}} shows an example of the body of a POST request to allow the traffic destined to 2001:db8::/32 and UDP port number 53, but to drop all fragmented packets. The following ACEs are defined (in this order):

* "drop-all-fragments" ACE: discards all fragments (including atomic fragments). That is, IPv6 packets that include a Fragment header (44) are dropped.
* "allow-dns-packets" ACE: accepts DNS packets destined to 2001:db8::/32.

~~~ json
{
  "ietf-access-control-list:acls": {
    "acl": [
      {
        "name": "dns-fragments",
        "type": "ipv6-acl-type",
        "aces": {
          "ace": [
            {
              "name": "drop-all-fragments",
              "matches": {
                "ipv6": {
                  "ietf-acl-enh:ipv6-fragment": {
                    "operator": "match",
                    "type": "isf"
                  }
                }
              },
              "actions": {
                "forwarding": "drop"
              }
            },
            {
              "name": "allow-dns-packets",
              "matches": {
                "ipv6": {
                  "destination-ipv6-network": "2001:db8::/32"
                },
                "udp": {
                  "destination-port": {
                    "operator": "eq",
                    "port": 53
                  }
                }
              },
              "actions": {
                "forwarding": "accept"
              }
            }
          ]
        }
      }
    ]
  }
}
~~~
{: #example_3 title="An Example Illustrating Filtering of IPv6 Fragmented Packets (Message Body)"}

## VLAN Filtering

{{example_7}} shows an ACL example to illustrate how to apply a VLAN range filter.

~~~ json
{
  "ietf-access-control-list:acls": {
    "acl": [
      {
        "name": "VLAN_FILTER",
        "aces": {
          "ace": [
            {
              "name": "1",
              "matches": {
                "ietf-acl-enh:vlan-filter": {
                  "lower-vlan": 10,
                  "upper-vlan": 20
                }
              },
              "actions": {
                "forwarding": "ietf-access-control-list:accept"
              }
            }
          ]
        }
      }
    ]
  }
}
~~~
{: #example_7 title="Example of VLAN Filter (Message Body)"}

## ISID Filtering

{{example_6}} shows an ACL example to illustrate the ISID range filtering.

~~~ json
{
  "ietf-access-control-list:acls": {
    "acl": [
      {
        "name": "test",
        "aces": {
          "ace": [
            {
              "name": "1",
              "matches": {
                "ietf-acl-enh:isid-filter": {
                  "lower-isid": 100,
                  "upper-isid": 200
                }
              },
              "actions": {
                "forwarding": "ietf-access-control-list:accept"
              }
            }
          ]
        }
      }
    ]
  }
}
~~~
{: #example_6 title="Example ISID Filter (Message Body)"}

## Rate-Limit

{{example_5}} shows an ACL example to rate-limit incoming SYNs during a SYN flood attack.

~~~ json
{
  "ietf-access-control-list:acls": {
    "acl": [
      {
        "name": "tcp-flags-example-with-rate-limit",
        "aces": {
          "ace": [
            {
              "name": "rate-limit-syn",
              "matches": {
                "tcp": {
                  "ietf-acl-enh:flags-bitmask": {
                    "operator": "match",
                    "bitmask": 2
                  }
                }
              },
              "actions": {
                "forwarding": "accept",
                "ietf-acl-enh:rate-limit": "20.00"
              }
            }
          ]
        }
      }
    ]
  }
}
~~~
{: #example_5 title="An Example of Rate-Limit Incoming TCP SYNs (Message Body)."}

# Acknowledgements
{:numbered="false"}

Many thanks to Jon Shallow and Miguel Cros for the review and comments to the document, including prior to publishing the document.

Thanks to Qiufang Ma, Victor Lopez, Joe Clarke, and Mahesh Jethanandani for the comments and suggestions.

Thanks to Lou Berger for Shepherding the document.

Thanks to David Black for the TSV review and Tim Wicinski for the intdir review.

The IANA-maintained modules were generated using an XSLT stylesheet from the 'iana-yang' project (https://github.com/llhotka/iana-yang).

This work is partially supported by the European Commission under   Horizon 2020 Secured autonomic traffic management for a Tera of SDN
flows (Teraflow) project (grant agreement number 101015857).
