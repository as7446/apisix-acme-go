package acme

import (
	"fmt"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/providers/dns/alidns"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/providers/dns/dnspod"
)

// newDNSChallengeProviderByName 精简版 DNS Provider 注册
// 只包含实际使用的 provider，避免 lego 全量注册导致二进制体积膨胀
func newDNSChallengeProviderByName(name string) (challenge.Provider, error) {
	switch name {
	case "cloudflare":
		return cloudflare.NewDNSProvider()
	case "dnspod":
		return dnspod.NewDNSProvider()
	case "alidns":
		return alidns.NewDNSProvider()
	default:
		return nil, fmt.Errorf("unsupported DNS provider: %s (supported: cloudflare, dnspod, alidns)", name)
	}
}
