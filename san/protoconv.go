package san

import (
	"net"

	"github.com/IPA-CyberLab/kmgm/pb"
)

func FromProtoStruct(s *pb.Names) (Names, error) {
	var ns Names
	if s == nil {
		return ns, nil
	}

	ns.DNSNames = append(ns.DNSNames, s.Dnsnames...)
	for _, e := range s.Ipaddrs {
		if ipaddr := net.ParseIP(e); ipaddr != nil {
			ns.IPAddrs = append(ns.IPAddrs, ipaddr)
		}
	}
	if err := ns.Verify(); err != nil {
		return Names{}, err
	}

	return ns, nil
}

func (ns Names) ToProtoStruct() *pb.Names {
	ss := make([]string, 0, len(ns.IPAddrs))
	for _, ip := range ns.IPAddrs {
		ss = append(ss, ip.String())
	}

	return &pb.Names{
		Dnsnames: append([]string{}, ns.DNSNames...),
		Ipaddrs:  ss,
	}
}
