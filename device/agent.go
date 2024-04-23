package device

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/spf13/cast"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

const agentBin = "/opt/agent/bin/agent"
const defaultSockFileDir = "/opt/agent/run/"
const defaultLoopCheckInterval = 5 * time.Second

var defaultAgent *Agent

type Agent struct {
	NodeID            uint `json:"node_id"`
	sockFile          string
	loopCheckInterval time.Duration
	device            *Device
	log               *Logger

	peers               map[string]*AgentPeer
	fakeUUIDToAllowedIP map[string]string
	fakeUUIDToUUID      map[string]string
	lock                sync.Mutex
}

type AgentPeer struct {
	peer         *Peer
	connectSince int64
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

		peers:               make(map[string]*AgentPeer),
		fakeUUIDToAllowedIP: make(map[string]string),
		fakeUUIDToUUID:      make(map[string]string),
	}

	go func() {
		err := agent.httpServe()
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

		disconnectTime := time.Now().Add(-time.Minute * 2).UnixNano()

		for pk, peer := range a.peers {
			if peer.peer.lastHandshakeNano.Load() < disconnectTime && peer.connectSince < disconnectTime {
				go func() {
					rxBytes := peer.peer.rxBytes.Load()
					txBytes := peer.peer.txBytes.Load()
					peer.peer.rxBytes.Store(0)
					peer.peer.txBytes.Store(0)

					peer.peer.endpoint.Lock()
					endpoint := peer.peer.endpoint.val
					peer.peer.endpoint.Unlock()
					realAddress := endpoint.DstToString()

					err := a.requestDisconnectToAgent(a.fakeUUIDToUUID[pk], realAddress, a.fakeUUIDToAllowedIP[pk], peer.connectSince, int64(rxBytes), int64(txBytes))
					if err != nil {
						a.log.Errorf("RequestDisconnectToAgent error: %v", err)
					}
				}()

				delete(a.peers, pk)
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

	fakeUUID := peer.handshake.remoteStatic.ToHex()
	if _, has := a.peers[fakeUUID]; !has {
		connectSince := time.Now().Unix()

		go func() {
			endpoint := peer.endpoint.val
			realAddress := endpoint.DstToString()

			err := a.requestConnectToAgent(a.fakeUUIDToUUID[fakeUUID], realAddress, a.fakeUUIDToAllowedIP[fakeUUID], connectSince)
			if err != nil {
				a.log.Errorf("RequestConnectToAgent error: %v", err)
			}

			peer.rxBytes.Store(0)
			peer.txBytes.Store(0)
		}()

		a.peers[fakeUUID] = &AgentPeer{
			peer:         peer,
			connectSince: connectSince,
		}
	}
}

const peerStr = `public_key=%s
replace_allowed_ips=true
allowed_ip=%s/32

`

func (a *Agent) AddPeer(peer agentAddPeerRequest) error {
	pubKey, err := base64.StdEncoding.DecodeString(peer.PublicKey)
	if err != nil {
		return err
	}

	publicKey := hex.EncodeToString(pubKey)
	buf := fmt.Sprintf(peerStr, publicKey, peer.AllowedIP)
	a.device.log.Verbosef("AddPeer: %s", buf)
	err = a.device.IpcSetOperation(strings.NewReader(buf))
	if err != nil {
		return err
	}

	a.lock.Lock()
	defer a.lock.Unlock()

	a.fakeUUIDToAllowedIP[publicKey] = peer.AllowedIP
	a.fakeUUIDToUUID[publicKey] = peer.UUID
	return nil
}

type agentAddPeerRequest struct {
	PublicKey string `json:"public_key"`
	AllowedIP string `json:"allowed_ip"`
	UUID      string `json:"uuid"`
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

func (a *Agent) httpServe() error {
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
				endpoint := peer.peer.endpoint.val
				realIP, _ := netip.ParseAddrPort(endpoint.DstToString())

				resp = append(resp, agentPeerResponse{
					NodeID:          int64(a.NodeID),
					UUID:            a.fakeUUIDToUUID[pk],
					FakeUUID:        pk,
					RealAddress:     realIP.Addr().String(),
					RealAddressPort: fmt.Sprintf("%d", realIP.Port()),
					VirtualAddress:  a.fakeUUIDToAllowedIP[pk],
					BytesReceived:   int64(peer.peer.txBytes.Load()),
					BytesSent:       int64(peer.peer.rxBytes.Load()),
					ConnectedSince:  peer.connectSince,
					Username:        peer.peer.handshake.remoteStatic.ToHex(),
				})
			}
			data, _ := json.Marshal(resp)
			_, _ = w.Write(data)
		} else if r.Method == http.MethodPost {
			var req agentAddPeerRequest
			err := json.NewDecoder(r.Body).Decode(&req)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			err = a.AddPeer(req)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			} else {
				w.WriteHeader(http.StatusOK)
			}

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
