module github.com/go-i2p/go-sshd

go 1.26.5

require (
	github.com/gliderlabs/ssh v0.3.8
	github.com/go-i2p/onramp v0.33.92
	github.com/google/shlex v0.0.0-20191202100458-e7afc7fbc510
	github.com/msteinert/pam v1.2.0
	github.com/pkg/sftp v1.13.11
	github.com/prometheus/client_golang v1.24.1
	github.com/sirupsen/logrus v1.10.2
	github.com/spf13/cobra v1.10.2
	github.com/stretchr/testify v1.12.1
	golang.org/x/crypto v0.57.0
)

require (
	github.com/anmitsu/go-shlex v0.0.0-20200514113438-38f4b401e2be // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/cretz/bine v0.2.0 // indirect
	github.com/go-i2p/i2pkeys v0.33.92 // indirect
	github.com/go-i2p/sam3 v0.33.92 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/kr/fs v0.1.0 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/prometheus/client_model v0.6.3 // indirect
	github.com/prometheus/common v0.71.0 // indirect
	github.com/prometheus/procfs v0.22.0 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
)

retract (
	v0.1.59999
	v0.1.5999
	v0.1.599
)
