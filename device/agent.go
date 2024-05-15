package device

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/spf13/cast"
	"golang.zx2c4.com/wireguard/utils"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

const (
	agentBin                 = "/opt/agent/bin/agent"
	defaultSockFileDir       = "/opt/agent/run/"
	defaultLoopCheckInterval = 5 * time.Second

	defaultClientIP     = "10.10.0.0"
	defaultClientIPMask = "255.255.0.0"
)

var defaultAgent *Agent

type Agent struct {
	NodeID            uint `json:"node_id"`
	sockFile          string
	loopCheckInterval time.Duration
	device            *Device
	log               *Logger

	peers map[string]*AgentPeer
	lock  sync.Mutex

	ipRange *utils.Range
}

type AgentPeer struct {
	peer         *Peer
	connectSince int64
	allowedIP    string
	uuid         string
	createTime   time.Time
}

func InitAgent(nodeID uint, device *Device, logger *Logger) {
	defaultAgent = NewAgent(nodeID, device, defaultLoopCheckInterval, logger)
}

func NewAgent(nodeID uint, device *Device, loopCheckInterval time.Duration, logger *Logger) *Agent {
	agent := &Agent{
		NodeID:            nodeID,
		sockFile:          fmt.Sprintf("%swg%d.sock", defaultSockFileDir, nodeID),
		loopCheckInterval: loopCheckInterval,
		device:            device,
		log:               logger,

		peers: make(map[string]*AgentPeer),
		ipRange: utils.NewCIDRRange(&net.IPNet{
			IP:   net.ParseIP(defaultClientIP),
			Mask: utils.ParseIPv4Mask(defaultClientIPMask),
		}),
	}

	go func() {
		err := agent.AgentHttpServer()
		if err != nil {
			fmt.Println(err)
		}
	}()
	go func() {
		err := agent.ClientHttpServer()
		if err != nil {
			fmt.Println(err)
		}
	}()
	go agent.LoopCheckPeers()
	return agent
}

func RequestHandshake(peer *Peer) {
	if defaultAgent != nil {
		go defaultAgent.RequestHandshake(peer)
	}
}

func (a *Agent) LoopCheckPeers() {
	loop := func() {
		a.lock.Lock()
		defer a.lock.Unlock()

		disconnectTime := time.Now().Add(-time.Minute * 4).UnixNano()
		waitHandshakeTime := time.Now().Add(-time.Second * 20).UnixNano()

		for pk, peer := range a.peers {
			if peer.connectSince != 0 && peer.peer.lastHandshakeNano.Load() < disconnectTime && peer.connectSince < disconnectTime {
				err := a.RemovePeer(pk)
				if err != nil {
					a.log.Errorf("Disconnect error: %v", err)
				}
				continue
			}

			if peer.connectSince == 0 && peer.createTime.UnixNano() < waitHandshakeTime {
				err := a.RemovePeer(pk)
				if err != nil {
					a.log.Errorf("RemovePeer error: %v", err)
				}
				continue
			}
		}
	}

	for {
		loop()
		time.Sleep(a.loopCheckInterval)
	}
}

func (a *Agent) RequestHandshake(peer *Peer) {
	a.lock.Lock()
	defer a.lock.Unlock()

	pk := peer.handshake.remoteStatic.ToHex()
	if agentPeer, has := a.peers[pk]; has && agentPeer.connectSince == 0 {
		connectSince := time.Now().Unix()

		go func() {
			endpoint := peer.endpoint.val
			realAddress := endpoint.DstToString()

			err := a.requestConnectToAgent(agentPeer.uuid, realAddress, agentPeer.allowedIP, connectSince)
			if err != nil {
				a.log.Errorf("RequestConnectToAgent error: %v", err)
			}

			peer.rxBytes.Store(0)
			peer.txBytes.Store(0)
		}()

		agentPeer.peer = peer
		agentPeer.connectSince = connectSince
	}
}

const removePeerStr = `public_key=%s
remove=true

`

func (a *Agent) RemovePeer(pk string) error {
	peer := a.peers[pk]

	if peer.connectSince != 0 {
		go func() {
			rxBytes := peer.peer.rxBytes.Load()
			txBytes := peer.peer.txBytes.Load()
			peer.peer.rxBytes.Store(0)
			peer.peer.txBytes.Store(0)

			peer.peer.endpoint.Lock()
			endpoint := peer.peer.endpoint.val
			realAddress := endpoint.DstToString()
			peer.peer.endpoint.Unlock()

			err := a.requestDisconnectToAgent(peer.uuid, realAddress, peer.allowedIP, peer.connectSince, int64(rxBytes), int64(txBytes))
			if err != nil {
				a.log.Errorf("RequestDisconnectToAgent error: %v", err)
			}
		}()
	}

	buf := fmt.Sprintf(removePeerStr, pk)
	a.device.log.Verbosef("RemovePeer: %s", buf)

	err := a.device.IpcSetOperation(strings.NewReader(buf))
	if err != nil {
		return fmt.Errorf("RemovePeer error: %v", err)
	}

	if a.peers[pk] != nil {
		err = a.ipRange.Release(net.ParseIP(a.peers[pk].allowedIP))
		if err != nil {
			return fmt.Errorf("release IP error: %v", err)
		}
	}

	delete(a.peers, pk)

	return nil
}

const addPeerStr = `public_key=%s
replace_allowed_ips=true
allowed_ip=%s/32

`

func (a *Agent) AddPeer(peer agentAddPeerRequest) error {
	pubKey, err := base64.StdEncoding.DecodeString(peer.PublicKey)
	if err != nil {
		return err
	}

	publicKey := hex.EncodeToString(pubKey)

	a.lock.Lock()
	defer a.lock.Unlock()

	if _, has := a.peers[publicKey]; has {
		_ = a.RemovePeer(publicKey)
	}

	buf := fmt.Sprintf(addPeerStr, publicKey, peer.AllowedIP)
	a.device.log.Verbosef("AddPeer: %s", buf)
	err = a.device.IpcSetOperation(strings.NewReader(buf))
	if err != nil {
		return err
	}

	a.peers[publicKey] = &AgentPeer{
		allowedIP:  peer.AllowedIP,
		uuid:       peer.UUID,
		createTime: time.Now(),
	}
	return nil
}

type agentAddPeerRequest struct {
	PublicKey string `json:"public_key"`
	AllowedIP string `json:"allowed_ip"`
	UUID      string `json:"uuid"`
}

type agentAddPeerResponse struct {
	AllowedIP string `json:"allowed_ip"`
}

type agentPeerResponse struct {
	NodeID          int64  `json:"node_id"`
	UUID            string `json:"uuid"`
	FakeUUID        string `json:"fake_uuid"`
	RealAddress     string `json:"real_address"`
	RealAddressPort string `json:"real_address_port"`
	VirtualAddress  string `json:"virtual_address"`
	BytesReceived   int64  `json:"bytes_received"`
	BytesSent       int64  `json:"bytes_sent"`
	ConnectedSince  int64  `json:"connected_since"`
	Username        string `json:"username"`
}

func (a *Agent) ClientHttpServer() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/add_peer", func(w http.ResponseWriter, r *http.Request) {
		var req agentAddPeerRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		a.log.Verbosef("[api] AddPeer: %v", req)

		if req.AllowedIP != "" {
			err = a.ipRange.Allocate(net.ParseIP(req.AllowedIP))
			if err != nil {
				req.AllowedIP = ""
			}
		}

		if req.AllowedIP == "" {
			ip, err := a.ipRange.AllocateNext()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			req.AllowedIP = ip.String()
		}

		err = a.AddPeer(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		resp := agentAddPeerResponse{
			AllowedIP: req.AllowedIP,
		}

		err = json.NewEncoder(w).Encode(resp)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
	})

	mux.HandleFunc("/remove_peer", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			PublicKey string `json:"public_key"`
		}
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		a.log.Verbosef("[api] RemovePeer: %s", req.PublicKey)

		pubKey, err := base64.StdEncoding.DecodeString(req.PublicKey)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		publicKey := hex.EncodeToString(pubKey)

		err = a.RemovePeer(publicKey)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
	})

	httpServer := &http.Server{
		Addr:    ":1444",
		Handler: mux,
	}
	return httpServer.ListenAndServe()
}

func (a *Agent) AgentHttpServer() error {
	_ = os.Remove(a.sockFile)
	l, err := net.Listen("unix", a.sockFile)
	if err != nil {
		return err
	}
	return http.Serve(l, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			a.lock.Lock()
			defer a.lock.Unlock()

			var resp = make([]agentPeerResponse, 0, len(a.peers))
			for pk, peer := range a.peers {
				if peer.peer == nil {
					continue
				}
				peer.peer.endpoint.Lock()
				endpoint := peer.peer.endpoint.val
				realIP, _ := netip.ParseAddrPort(endpoint.DstToString())
				peer.peer.endpoint.Unlock()

				resp = append(resp, agentPeerResponse{
					NodeID:          int64(a.NodeID),
					UUID:            peer.uuid,
					FakeUUID:        pk,
					RealAddress:     realIP.Addr().String(),
					RealAddressPort: fmt.Sprintf("%d", realIP.Port()),
					VirtualAddress:  peer.allowedIP,
					BytesReceived:   int64(peer.peer.txBytes.Load()),
					BytesSent:       int64(peer.peer.rxBytes.Load()),
					ConnectedSince:  peer.connectSince,
					Username:        peer.peer.handshake.remoteStatic.ToHex(),
				})
			}
			data, _ := json.Marshal(resp)
			_, _ = w.Write(data)
		} else {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}

	}))
}

func (a *Agent) requestConnectToAgent(uuid string, realAddress string, virtualAddress string, connectSince int64) error {
	cmd := exec.Command(agentBin, "wgpeer", "connect", cast.ToString(a.NodeID), realAddress, virtualAddress, uuid, cast.ToString(connectSince))
	out, err := cmd.Output()
	if err != nil {
		return err
	}
	a.log.Verbosef("requestConnectToAgent: cmd(%s), out(%s)", cmd.String(), out)
	return nil
}

func (a *Agent) requestDisconnectToAgent(uuid string, realAddress string, virtualAddress string, connectSince int64, bytesSent int64, bytesReceived int64) error {
	cmd := exec.Command(agentBin, "wgpeer", "disconnected", cast.ToString(a.NodeID), realAddress, virtualAddress,
		uuid, cast.ToString(connectSince), cast.ToString(bytesSent), cast.ToString(bytesReceived))
	out, err := cmd.Output()
	if err != nil {
		return err
	}
	a.log.Verbosef("requestDisconnectToAgent: cmd(%s), out(%s)", cmd.String(), out)
	return nil
}
