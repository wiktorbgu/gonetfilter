package expr

import (
	"testing"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

func TestExprFromNameSocketAndTProxy(t *testing.T) {
	tests := []struct {
		name string
		expr Any
	}{
		{name: "socket", expr: &Socket{}},
		{name: "tproxy", expr: &TProxy{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := exprFromName(tt.name)
			if got == nil {
				t.Fatalf("exprFromName(%q) returned nil", tt.name)
			}
			switch tt.name {
			case "socket":
				if _, ok := got.(*Socket); !ok {
					t.Fatalf("got %T, want *Socket", got)
				}
			case "tproxy":
				if _, ok := got.(*TProxy); !ok {
					t.Fatalf("got %T, want *TProxy", got)
				}
			}
		})
	}
}

func TestDecodeSocketAndTProxyExpressions(t *testing.T) {
	tests := []struct {
		name  string
		expr  Any
		check func(*testing.T, Any)
	}{
		{
			name: "socket",
			expr: &Socket{Key: SocketKeyTransparent, Register: 7},
			check: func(t *testing.T, got Any) {
				e, ok := got.(*Socket)
				if !ok {
					t.Fatalf("got %T, want *Socket", got)
				}
				if e.Key != SocketKeyTransparent || e.Register != 7 {
					t.Fatalf("decoded socket = %+v", e)
				}
			},
		},
		{
			name: "tproxy",
			expr: &TProxy{Family: unix.NFPROTO_IPV6, RegAddr: 1, RegPort: 2},
			check: func(t *testing.T, got Any) {
				e, ok := got.(*TProxy)
				if !ok {
					t.Fatalf("got %T, want *TProxy", got)
				}
				if e.Family != unix.NFPROTO_IPV6 || e.RegAddr != 1 || e.RegPort != 2 {
					t.Fatalf("decoded tproxy = %+v", e)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Exercise the nested expression-list shape used by nftables rules.
			exprBytes, err := tt.expr.marshal(unix.NFPROTO_INET)
			if err != nil {
				t.Fatal(err)
			}
			listBytes, err := netlink.MarshalAttributes([]netlink.Attribute{{
				Type: unix.NLA_F_NESTED | unix.NFTA_LIST_ELEM,
				Data: exprBytes,
			}})
			if err != nil {
				t.Fatal(err)
			}
			ad, err := netlink.NewAttributeDecoder(listBytes)
			if err != nil {
				t.Fatal(err)
			}
			if !ad.Next() {
				t.Fatal("missing nested expression list element")
			}
			got, err := exprsFromBytes(unix.NFPROTO_INET, ad)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != 1 {
				t.Fatalf("decoded %d expressions, want 1", len(got))
			}
			tt.check(t, got[0])
		})
	}
}
