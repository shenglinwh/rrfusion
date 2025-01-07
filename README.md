# RRFuision: A Routing Registry Fusion System

A Routing Registry Fusion System designed to integrate and reconcile multi-source data (IRR, RPKI, VRO), solving inconsistencies and enhancing global routing security. By leveraging advanced algorithms, the system ensures real-time data verification, consistency, and automated route policy optimization, empowering network operators to safeguard against threats like BGP hijacking.


* `/lib` contains a library to create your own server and client.
* `/prefixfile` contains the structure of a JSON export file and signing capabilities.
* `/cmd/rrconf/rrconf.go` configures and generates the customizable routing registry policy by combining multiple sources.
* `/cmd/stayrtr/stayrtr.go` is a simple implementation that fetches a list and offers it to a router.
* `/cmd/rtrdump/rtrdump.go` allows copying the PDUs sent by a RTR server as a JSON file.
* `/cmd/rtrmon/rtrmon.go` compare and monitor two RTR servers (using RTR and/or JSON), outputs diff and Prometheus metrics.

The module that provides a routing registry to the router using the [stayrtr](https://github.com/bgp/stayrtr). 


## Features of the server

* Supports the Verifiable Route Origin (VRO) draft
* Support multi-source data cross-validation including time, authorization, and statistics
* Dissemination of validated ROA and BGPsec payloads
* Refreshes a JSON list of prefixes
* Automatic expiration of outdated information (when using JSON produced by [rpki-client](https://www.rpki-client.org))
* Prometheus metrics
* TLS
* SSH


## Features of the RTR API

* Protocol v0 of [RFC6810](https://tools.ietf.org/html/rfc6810)
* Protocol v1 of [RFC8210](https://tools.ietf.org/html/rfc8210)
* Event-driven API
* TLS
* SSH

## Install it

You need a working [Go environment](https://golang.org/doc/install) (1.17 or newer).
This project also uses [Go Modules](https://github.com/golang/go/wiki/Modules).

```bash
$ git clone git@github.com:shenglinwh/rrfusion.git && cd rrfusion
$ go build cmd/rrconf/rrconf.go
$ go build cmd/stayrtr/stayrtr.go
```

## Run it

Once you have the binary files rrconf and stayrtr. You can configure the fusion rules as required (see conf.yaml for configuration rules), and run the rtr server.


```bash
$ ./rrconf -config.file config.yaml 
$ ./stayrtr -slurm cache/rrfusion.json
```

Please refer to the [stayrtr documentation](https://github.com/bgp/stayrtr/blob/master/README.md) for more information on how to use it in TLS and SSH modes.

## Debug the content

You can check the content provided over RTR with rtrdump tool

```bash
$ ./rtrdump -connect 127.0.0.1:8282 -file debug.json
```

You can also fetch the re-generated JSON from the `-export.path` endpoint (default: `http://localhost:9847/rpki.json`)

## Monitoring rtr and JSON endpoints

With `rtrmon` you can monitor the difference between rtr and/or JSON endpoints.
You can use this to, for example, track that your StayRTR instance is still in
sync with your RP instance. Or to track that multiple RP instances are in sync.

If your CA software has an endpoint that exposes objects in the standard JSON
format, you can even make sure that the objects that your CA software should
generate actually are visible to RPs, to monitor the full cycle.

```
$ ./rtrmon \
  -primary.host tcp://rtr.rpki.cloudflare.com:8282 \
  -secondary.host https://console.rpki-client.org/rpki.json \
  -secondary.refresh 30s \
  -primary.refresh 30s
```

rtrmon has two endpoints:
  * `/metrics`: for prometheus metrics
  * `/diff.json` (default, can be overridden by the `-file` flag): for a JSON file containing the difference between sources

### diff

The `diff.json` endpoint contains four keys.

  * `metadata-primary`: configuration of the primary source
  * `metadata-secondary`: configuration of the secondary source
  * `only-primary`: objects in the primary source but not in the secondary source.
  * `only-secondary`: objects in the secondary source but not in the primary source.

### Metrics
By default the Prometheus endpoint is on `http://[host]:9866/metrics`.
Among others, this endpoint contains the following metrics:

  * `rpki_vrps`: Current number of VRPS and current difference between the primary and secondary.
  * `rtr_serial`: Serial of the rtr session (when applicable).
  * `rtr_session`: Session ID of the RTR session.
  * `rtr_state`: State of the rtr session (up/down).
  * `update`: Timestamp of the last update.
  * `vrp_diff`: The number of VRPs which were seen in `lhs` at least `visibility_seconds` ago not in `rhs`.

Using these metrics you can visualise or alert on, for example:

  * Unexpected behaviour
    * Did the number of VRPs drop more than 10% compared to the 24h average?
  * Liveliness
    * Is the RTR serial increasing?
    * Is rtrmon still getting updates?
  * Convergence
    * Do both my RP instances see the same objects eventually?
    * Are objects first visible in the JSON `difference` (e.g. 1706) seconds ago visible in RTR?

When the objects are not converging, the `diff.json` endpoint may help while investigating the issues.

## Data sources
The RRFusion system can support multiple data sources, including IRR, RPKI, VRO and etc.

### VRO

The VRO data source is generated by the VRO validator tool, and the JSON source follows the following schema:

```
{
  "smg": [
    {
      "prefix": "10.0.0.0/24",
      "asns": [
        65001,
        54874
      ]
    },
    ...
  ]
}
```

### IRR

The IRR data source include the following sources defautly:

* ALTDB: "ftp://ftp.radb.net/radb/dbase/altdb.db.gz"
* BBOI: "ftp://ftp.radb.net/radb/dbase/bboi.db.gz"
* BELL: "ftp://ftp.radb.net/radb/dbase/bell.db.gz"
* CANARIE: "ftp://ftp.radb.net/radb/dbase/canarie.db.gz"
* JPIRR: "ftp://ftp.radb.net/radb/dbase/jpirr.db.gz"
* NESTEGG: "ftp://ftp.radb.net/radb/dbase/nestegg.db.gz"
* NTTCOM: "ftp://ftp.radb.net/radb/dbase/nttcom.db.gz"
* PANIX: "ftp://ftp.radb.net/radb/dbase/panix.db.gz"
* RADB: "ftp://ftp.radb.net/radb/dbase/radb.db.gz"
* REACH: "ftp://ftp.radb.net/radb/dbase/reach.db.gz"
* TC: "ftp://ftp.radb.net/radb/dbase/tc.db.gz"
* LEVEL3: "ftp://rr.Level3.net/level3.db.gz"
* WCGDB: "ftp://rr.Level3.net/wcgdb.db.gz"
* IDNIC: "ftp://irr-mirror.idnic.net/idnic.db.gz"
* ARIN: "ftp://ftp.arin.net/pub/rr/arin.db.gz"
* AFRINIC: "ftp://ftp.afrinic.net/pub/dbase/afrinic.db.gz"
* APNIC: "ftp://ftp.apnic.net/pub/apnic/whois/apnic.db.route.gz"
* APNIC6: "ftp://ftp.apnic.net/pub/apnic/whois/apnic.db.route6.gz"
* LACNIC: "https://ftp.lacnic.net/lacnic/irr/lacnic.db.gz"
* RIPR-NONAUTH: "ftp://ftp.ripe.net/ripe/dbase/split/ripe-nonauth.db.route.gz"
* RIPE-NONAUTH6: "ftp://ftp.ripe.net/ripe/dbase/split/ripe-nonauth.db.route6.gz"
* RIPE: "ftp://ftp.ripe.net/ripe/dbase/split/ripe.db.route.gz"
* RIPE6: "ftp://ftp.ripe.net/ripe/dbase/split/ripe.db.route6.gz"

### RPKI
Use your own validator, as long as the JSON source follows the following schema:

```
{
  "roas": [
    {
      "prefix": "10.0.0.0/24",
      "maxLength": 24,
      "asn": 65001
    },
    ...
  ]
}
```

* **Third-party JSON formatted VRP exports:**
  * [console.rpki-client.org](https://console.rpki-client.org/rpki.json) (default, based on OpenBSD's `rpki-client`)
  * [NTT](https://rpki.gin.ntt.net/api/export.json) (based on OpenBSD's `rpki-client`)

By default, the session ID will be randomly generated. The serial will start at zero.

Make sure the refresh rate of StayRTR is more frequent than the refresh rate of the JSON.

## TODO

* Support for other data sources (e.g. MRT, PFX2AS, etc.)
* Support for other routing policy (e.g. autnum, as-set, route-set, etc.)
* Support for plugin-based validation and dissemination algorithms
* Support route leaking detection and mitigation

## License

Licensed under the BSD 3 License.
