package device

import (
	"golang.zx2c4.com/wireguard/conn"
	"sync"
	"time"
)

type StatusCallback func(status int, msg string)

const (
	StatusHandshakeSuccess int = 1
	StatusHandshakeFailed  int = 2
	StatusClose            int = 4

	LoopCheckInterval = 5 * time.Second

	CallbackMsgHandshakeSuccess = "handshake success"
	CallbackMsgHandshakeFailed  = "handshake failed"
	CallbackMsgCloseTimeout     = "timeout"
)

func (device *Device) LoopCheckDevice() {
	if device.iosClientCallback == nil {
		device.log.Errorf("close iosClientCallback is null")
		return
	}
	for {
		device.peers.RLock()
		peers := device.peers.keyMap
		device.peers.RUnlock()
		if len(peers) == 1 {
			last := conn.LastHeartbeat.Load()
			device.log.Verbosef("last:\t%d\nnow:\t%d\n\n", last/1e9, time.Now().UnixNano()/1e9)
			if last < time.Now().Add(-time.Minute*2).UnixNano() {
				if device.iosClientCallback != nil {
					device.iosClientCallback(StatusClose, "timeout")
				} else {
					device.log.Errorf("close iosClientCallback is null")
				}
				device.Close()
			}
		}
		time.Sleep(LoopCheckInterval)
	}
}

var handshakeStatusMap sync.Map

func (device *Device) StartHandshake(peerName string) {
	device.log.Verbosef("start handshake with %s", peerName)
	ch := make(chan struct{})
	if _, store := handshakeStatusMap.LoadOrStore(peerName, ch); store {
		return
	}
	go func() {
		select {
		case <-time.After(5 * time.Second):
			device.log.Errorf("handshake timeout")
			if device.iosClientCallback != nil {
				device.iosClientCallback(StatusHandshakeFailed, "timeout")
			}
		case <-ch:
			device.log.Verbosef("handshake success")
			if device.iosClientCallback != nil {
				device.iosClientCallback(StatusHandshakeSuccess, "handshake success")
			}
		}
	}()
}

func (device *Device) ResponseHandshake(peerName string) {
	device.log.Verbosef("response handshake with %s", peerName)
	if ch, ok := handshakeStatusMap.Load(peerName); ok {
		select {
		case ch.(chan struct{}) <- struct{}{}:
		default:
		}
	}
}
