module github.com/metacubex/mihomo

go 1.25.5

require (
	filippo.io/edwards25519 v1.1.0
	github.com/bahlo/generic-list-go v0.2.0
	github.com/coreos/go-iptables v0.8.0
	github.com/dlclark/regexp2 v1.11.5
	github.com/enfein/mieru/v3 v3.26.2
	github.com/gobwas/ws v1.4.0
	github.com/gofrs/uuid/v5 v5.4.0
	github.com/golang/snappy v1.0.0
	github.com/insomniacslk/dhcp v0.0.0-20250109001534-8abf58130905
	github.com/klauspost/compress v1.18.0 // lastest version compatible with golang1.20
	github.com/mdlayher/netlink v1.7.3-0.20250113171957-fbb4dce95f42
	github.com/metacubex/amneziawg-go v0.0.0-20251104174305-5a0e9f7e361d
	github.com/metacubex/bart v0.26.0
	github.com/metacubex/bbolt v0.0.0-20250725135710-010dbbbb7a5b
	github.com/metacubex/blake3 v0.1.0
	github.com/metacubex/chacha v0.1.5
	github.com/metacubex/chi v0.1.0
	github.com/metacubex/cpu v0.1.0
	github.com/metacubex/fswatch v0.1.1
	github.com/metacubex/gopacket v1.1.20-0.20230608035415-7e2f98a3e759
	github.com/metacubex/http v0.1.0
	github.com/metacubex/kcp-go v0.0.0-20260105040817-550693377604
	github.com/metacubex/mlkem v0.1.0
	github.com/metacubex/quic-go v0.59.1-0.20260112033758-aa29579f2001
	github.com/metacubex/randv2 v0.2.0
	github.com/metacubex/restls-client-go v0.1.7
	github.com/metacubex/sing v0.5.6
	github.com/metacubex/sing-mux v0.3.4
	github.com/metacubex/sing-quic v0.0.0-20260112044712-65d17608159e
	github.com/metacubex/sing-shadowsocks v0.2.12
	github.com/metacubex/sing-shadowsocks2 v0.2.7
	github.com/metacubex/sing-shadowtls v0.0.0-20250503063515-5d9f966d17a2
	github.com/metacubex/sing-tun v0.4.11
	github.com/metacubex/sing-vmess v0.2.4
	github.com/metacubex/sing-wireguard v0.0.0-20250503063753-2dc62acc626f
	github.com/metacubex/smux v0.0.0-20260105030934-d0c8756d3141
	github.com/metacubex/tfo-go v0.0.0-20251130171125-413e892ac443
	github.com/metacubex/tls v0.1.1
	github.com/metacubex/utls v1.8.4
	github.com/metacubex/wireguard-go v0.0.0-20250820062549-a6cecdd7f57f
	github.com/miekg/dns v1.1.63 // lastest version compatible with golang1.20
	github.com/mroth/weightedrand/v2 v2.1.0
	github.com/openacid/low v0.1.21
	github.com/oschwald/maxminddb-golang v1.12.0 // lastest version compatible with golang1.20
	github.com/sagernet/netlink v0.0.0-20240612041022-b9a21c07ac6a // indirect
	github.com/samber/lo v1.52.0
	github.com/sirupsen/logrus v1.9.3
	github.com/stretchr/testify v1.11.1
	github.com/vmihailenco/msgpack/v5 v5.4.1
	github.com/wk8/go-ordered-map/v2 v2.1.8
	gitlab.com/go-extension/aes-ccm v0.0.0-20230221065045-e58665ef23c7
	go.uber.org/automaxprocs v1.6.0
	go4.org/netipx v0.0.0-20231129151722-fdeea329fbba
	golang.org/x/crypto v0.45.0 // lastest version compatible with golang1.20
	golang.org/x/exp v0.0.0-20250620022241-b7579e27df2b // lastest version compatible with golang1.20
	golang.org/x/net v0.47.0 // lastest version compatible with golang1.20
	golang.org/x/sync v0.18.0 // lastest version compatible with golang1.20
	golang.org/x/sys v0.38.0 // lastest version compatible with golang1.20
	google.golang.org/protobuf v1.36.6 // lastest version compatible with golang1.20
	gopkg.in/yaml.v3 v3.0.1
)

require tailscale.com v1.92.5

require (
	github.com/RyuaNerin/go-krypto v1.3.0 // indirect
	github.com/Yawning/aez v0.0.0-20211027044916-e49e68abd344 // indirect
	github.com/ajg/form v1.5.1 // indirect
	github.com/akutz/memconn v0.1.0 // indirect
	github.com/alexbrainman/sspi v0.0.0-20231016080023-1a75b4708caa // indirect
	github.com/andybalholm/brotli v1.1.0 // indirect
	github.com/buger/jsonparser v1.1.1 // indirect
	github.com/coder/websocket v1.8.12 // indirect
	github.com/creachadair/msync v0.7.1 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/dblohm7/wingoes v0.0.0-20240119213807-a09d6be7affa // indirect
	github.com/ericlagergren/aegis v0.0.0-20250325060835-cd0defd64358 // indirect
	github.com/ericlagergren/polyval v0.0.0-20220411101811-e25bc10ba391 // indirect
	github.com/ericlagergren/siv v0.0.0-20220507050439-0b757b3aa5f1 // indirect
	github.com/ericlagergren/subtle v0.0.0-20220507045147-890d697da010 // indirect
	github.com/fsnotify/fsnotify v1.9.0 // indirect
	github.com/fxamacker/cbor/v2 v2.7.0 // indirect
	github.com/gaissmai/bart v0.18.0 // indirect
	github.com/gaukas/godicttls v0.0.4 // indirect
	github.com/go-json-experiment/json v0.0.0-20250813024750-ebf49471dced // indirect
	github.com/go-ole/go-ole v1.3.0 // indirect
	github.com/gobwas/httphead v0.1.0 // indirect
	github.com/gobwas/pool v0.2.1 // indirect
	github.com/godbus/dbus/v5 v5.1.1-0.20230522191255-76236955d466 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/google/btree v1.1.3 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/google/pprof v0.0.0-20240727154555-813a5fbdbec8 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/hdevalence/ed25519consensus v0.2.0 // indirect
	github.com/jsimonetti/rtnetlink v1.4.0 // indirect
	github.com/klauspost/cpuid/v2 v2.2.6 // indirect
	github.com/klauspost/reedsolomon v1.12.3 // indirect
	github.com/mailru/easyjson v0.7.7 // indirect
	github.com/mdlayher/socket v0.5.0 // indirect
	github.com/metacubex/ascon v0.1.0 // indirect
	github.com/metacubex/gvisor v0.0.0-20251227095601-261ec1326fe8 // indirect
	github.com/metacubex/hkdf v0.1.0 // indirect
	github.com/metacubex/hpke v0.1.0 // indirect
	github.com/metacubex/nftables v0.0.0-20250503052935-30a69ab87793 // indirect
	github.com/metacubex/qpack v0.6.0 // indirect
	github.com/metacubex/yamux v0.0.0-20250918083631-dd5f17c0be49 // indirect
	github.com/mitchellh/go-ps v1.0.0 // indirect
	github.com/oasisprotocol/deoxysii v0.0.0-20220228165953-2091330c22b7 // indirect
	github.com/pierrec/lz4/v4 v4.1.21 // indirect
	github.com/pires/go-proxyproto v0.8.1 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/prometheus-community/pro-bing v0.4.0 // indirect
	github.com/safchain/ethtool v0.3.0 // indirect
	github.com/sina-ghaderi/poly1305 v0.0.0-20220724002748-c5926b03988b // indirect
	github.com/sina-ghaderi/rabaead v0.0.0-20220730151906-ab6e06b96e8c // indirect
	github.com/sina-ghaderi/rabbitio v0.0.0-20220730151941-9ce26f4f872e // indirect
	github.com/tailscale/certstore v0.1.1-0.20231202035212-d3fa0460f47e // indirect
	github.com/tailscale/go-winio v0.0.0-20231025203758-c4f33415bf55 // indirect
	github.com/tailscale/goupnp v1.0.1-0.20210804011211-c64d0f06ea05 // indirect
	github.com/tailscale/hujson v0.0.0-20221223112325-20486734a56a // indirect
	github.com/tailscale/peercred v0.0.0-20250107143737-35a0c7bd7edc // indirect
	github.com/tailscale/web-client-prebuilt v0.0.0-20250124233751-d4cd19a26976 // indirect
	github.com/tailscale/wireguard-go v0.0.0-20250716170648-1d0488a3d7da // indirect
	github.com/u-root/uio v0.0.0-20240224005618-d2acac8f3701 // indirect
	github.com/vishvananda/netns v0.0.5 // indirect
	github.com/vmihailenco/tagparser/v2 v2.0.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	gitlab.com/yawning/bsaes.git v0.0.0-20190805113838-0a714cd429ec // indirect
	go4.org/mem v0.0.0-20240501181205-ae6ca9944745 // indirect
	golang.org/x/mod v0.30.0 // indirect
	golang.org/x/oauth2 v0.30.0 // indirect
	golang.org/x/term v0.37.0 // indirect
	golang.org/x/text v0.31.0 // indirect
	golang.org/x/time v0.11.0 // indirect
	golang.org/x/tools v0.39.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
	golang.zx2c4.com/wireguard/windows v0.5.3 // indirect
	gvisor.dev/gvisor v0.0.0-20250205023644-9414b50a5633 // indirect
)
