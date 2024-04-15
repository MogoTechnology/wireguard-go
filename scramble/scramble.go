package scramble

import (
	"golang.org/x/net/ipv6"
)

var key = []byte("mogo2022")

func ScrambleMessageRecv(msgs *[]ipv6.Message, numMsgs int) {
	// scramble the message
	for i := 0; i < numMsgs; i++ {
		msg := (*msgs)[i]
		for i2, buffer := range msg.Buffers {
			n := msg.N
			XORBuffer(buffer[:n])
			(*msgs)[i].Buffers[i2] = buffer
		}
	}
}

func ScrambleMessageSend(msgs *[]ipv6.Message, numMsgs int) {
	// scramble the message
	for i := 0; i < numMsgs; i++ {
		msg := (*msgs)[i]
		for i2, buffer := range msg.Buffers {
			n := len(buffer)
			XORBuffer(buffer[:n])
			(*msgs)[i].Buffers[i2] = buffer
		}
	}
}

func XORBuffer(buf []byte) {
	for i := 0; i < len(buf); i++ {
		buf[i] ^= key[i%len(key)]
	}
}
