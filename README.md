# DNSFronter

## Overview

A simple tool that acts as a proxy DNS server for situations where you have an upstream program handling DNS but wish to insert some specific records. For example, making use of a tool such as Evilginx2 but wishing to assign additional DNS records beyond those defined in your phishlets.

## Usage 

- Add your DNS records to records.txt
- Add any deny-listed IP addresses to denylist.txt
- Set the upstream IP address in the "UPSTREAM_SERVER" field in dnsfronter.py
- Execute the dnsfronter.py

## Required modules 

- dnslib 