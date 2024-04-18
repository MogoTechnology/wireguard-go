package scramble

import (
	"errors"
	"golang.org/x/net/ipv6"
	"strings"
)

var key = []byte("")
var scramble = false

func SetupKey(newKey string) error {
	scrambleArr := strings.Split(newKey, " ")
	if len(scrambleArr) != 2 {
		return errors.New("invalid scramble key")
	}
	scrambleType := scrambleArr[0]
	scrambleKey := scrambleArr[1]

	switch scrambleType {
	case "obfuscate":
		scramble = true
		key = []byte(scrambleKey)
	default:
		return errors.New("invalid scramble key")
	}

	return nil
}

func ScrambleMessageRecv(msgs *[]ipv6.Message, numMsgs int) {
	if !scramble {
		return
	}
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
	if !scramble {
		return
	}
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
