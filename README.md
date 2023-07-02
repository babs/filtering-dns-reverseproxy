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
rules:
  example.org:
    - name: allow NS and SOA queries
      match:
        query types:
          - NS
          - SOA
          - CAA
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
        source ips:
          - 10.0.0.0/8
          - 198.18.0.0/15
      then:
        action: forward
        targets:
          - "192.168.1.1:53"
          - "192.168.1.2:53"

    - name: fallback
      then:
        action: refused

```