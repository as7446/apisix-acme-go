package main

// The blank imports below register common DNS providers with lego so they can be
// referenced via config.AcmeDNSProvider and dns.NewDNSChallengeProviderByName.
import (
	//_ "github.com/go-acme/lego/v4/providers/dns/acmedns"
	//_ "github.com/go-acme/lego/v4/providers/dns/alidns"
	//_ "github.com/go-acme/lego/v4/providers/dns/azure"
	//_ "github.com/go-acme/lego/v4/providers/dns/azuredns"
	//_ "github.com/go-acme/lego/v4/providers/dns/cloudflare"
	//_ "github.com/go-acme/lego/v4/providers/dns/digitalocean"
	//_ "github.com/go-acme/lego/v4/providers/dns/dnsimple"
	_ "github.com/go-acme/lego/v4/providers/dns/dnspod"
	//_ "github.com/go-acme/lego/v4/providers/dns/exec"
	//_ "github.com/go-acme/lego/v4/providers/dns/gandi"
	//_ "github.com/go-acme/lego/v4/providers/dns/gcloud"
	//_ "github.com/go-acme/lego/v4/providers/dns/godaddy"
	//_ "github.com/go-acme/lego/v4/providers/dns/huaweicloud"
	//_ "github.com/go-acme/lego/v4/providers/dns/inwx"
	//_ "github.com/go-acme/lego/v4/providers/dns/namecheap"
	//_ "github.com/go-acme/lego/v4/providers/dns/namedotcom"
	//_ "github.com/go-acme/lego/v4/providers/dns/ns1"
	//_ "github.com/go-acme/lego/v4/providers/dns/oraclecloud"
	//_ "github.com/go-acme/lego/v4/providers/dns/ovh"
	//_ "github.com/go-acme/lego/v4/providers/dns/pdns"
	//_ "github.com/go-acme/lego/v4/providers/dns/porkbun"
	//_ "github.com/go-acme/lego/v4/providers/dns/route53"
	//_ "github.com/go-acme/lego/v4/providers/dns/tencentcloud"
	//_ "github.com/go-acme/lego/v4/providers/dns/transip"
	//_ "github.com/go-acme/lego/v4/providers/dns/vultr"
)
