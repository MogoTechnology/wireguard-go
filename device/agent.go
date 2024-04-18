package device

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"
)

const defaultSockFileDir = "/opt/agent/run/"
const defaultLoopCheckInterval = 5 * time.Second

var defaultAgent *Agent

type Agent struct {
	NodeID            uint `json:"node_id"`
	sockFile          string
	loopCheckInterval time.Duration
	device            *Device

	peers map[string]*AgentPeer
}

type AgentPeer struct {
	NodeID          int64  `json:"node_id"`
	CommonName      string `json:"common_name"`
	RealAddress     string `json:"real_address"`
	RealAddressPort string `json:"real_address_port"`
	VirtualAddress  string `json:"virtual_address"`
	BytesReceived   int64  `json:"bytes_received"`
	BytesSent       int64  `json:"bytes_sent"`
	ConnectedSince  int64  `json:"connected_since"`
	ConnectEndAt    int64  `json:"connect_end_at"`
	Username        string `json:"username"`
}

func InitAgent(nodeID uint, device *Device) {
	defaultAgent = NewAgent(nodeID, device, defaultLoopCheckInterval)
}

func NewAgent(nodeID uint, device *Device, loopCheckInterval time.Duration) *Agent {
	agent := &Agent{
		NodeID:            nodeID,
		sockFile:          fmt.Sprintf("%swg%d.sock", defaultSockFileDir, nodeID),
		loopCheckInterval: loopCheckInterval,
		device:            device,

		peers: make(map[string]*AgentPeer),
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

func (a *Agent) LoopCheckPeers() {

}

func (a *Agent) NewHandshake() {

}

func (a *Agent) httpServe() error {
	_ = os.Remove(a.sockFile)
	l, err := net.Listen("unix", a.sockFile)
	if err != nil {
		return err
	}
	return http.Serve(l, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"status":  "ok",
			"message": "pong",
		}
		data, _ := json.Marshal(resp)
		_, _ = w.Write(data)
	}))
}
