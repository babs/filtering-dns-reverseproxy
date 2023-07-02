Filtering DNS Reverse Proxy
===

A simple Filtering DNS Reverse Proxy allowing to expose publicly part of some zones (ie lets encrypt certs, domain delegation etc) without leaking private informations without falling into split horizon DNS.

Notes
---

- Be sure to disable recursion and additional on upstream server, for example on bind:

```
options {
  // [...]
  recursion no;
  additional-from-auth no;
  additional-from-cache no;
  // [...]
};
```

Config
---

Available actions:
 - `forward`: forward the query to a target taken randomly in the given `targets` list
 - `refused`: deliberately reply with a refused message
 - `failed`: deliberately reply with a fail message

Queries are normlized and canonicalized to lower case and trailing dot. Don't forget the later in patters.

```yaml
listen:
  udp:
    port: 53
  tcp:
    port: 53

x-private-ips: &x-private-ips
- 10.0.0.0/8
- 100.64.0.0/10
- 172.16.0.0/12
- 192.168.0.0/16
- fdff:ffff:ffff::/48

rules:
  example.org:
    - name: allow NS and SOA queries
      match:
        query types:
          - NS
          - SOA
          - CAA
          - MX
          - SRV
      then:
        action: forward
        targets:
          - "192.168.1.1:53"
          - "192.168.1.2:53"

    - name: allo TXT for lets encrypt
      match:
        query types:
          - TXT
        patterns:
          - ^_acme-challenge\..+$
      then:
        action: forward
        targets:
          - "192.168.1.1:53"
          - "192.168.1.2:53"

    - name: allow any query matching begining with ns
      description:
      match:
        patterns:
          - ^ns
      then:
        action: forward
        targets:
          - "192.168.1.1:53"
          - "192.168.1.2:53"

    - name: allow any query from those IPs
      description:
      match:
        source ips: *x-private-ips
      then:
        action: forward
        targets:
          - "192.168.1.1:53"
          - "192.168.1.2:53"

    - name: fallback
      then:
        action: refused


  subdomain.example.org:
    - name: allow NS and SOA queries
      match:
        query types:
          - NS
          - SOA
          - CAA
          - MX
          - SRV
      then:
        action: forward
        targets:
          - "192.168.1.1:53"
          - "192.168.1.2:53"

    - name: allo TXT for lets encrypt
      match:
        query types:
          - TXT
        patterns:
          - ^_acme-challenge\..+$
      then:
        action: forward
        targets:
          - "192.168.1.1:53"
          - "192.168.1.2:53"

    - name: allow internal ips from internal hosts
      description:
      match:
        source ips: *x-private-ips
      then:
        action: forward
        targets:
          - "192.168.1.1:53"
          - "192.168.1.2:53"


    - name: filter internal ips
      description:
      match:
        query types:
          - A
          - AAAA
          - ANY
      then:
        action: forward
        targets:
          - "192.168.1.1:53"
          - "192.168.1.2:53"
        filter:
          answered address:
            not in: *x-private-ips

    # Internal IP being filtered, let's fall back
    - name: fallback
      then:
        action: forward
        targets:
          - "192.168.1.1:53"
          - "192.168.1.2:53"

```