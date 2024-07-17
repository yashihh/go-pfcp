// Copyright 2019-2022 go-pfcp authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

package ie

import (
	"io"
	"net"
)

// NewFGUserPlaneNode creates a new FGUserPlaneNode IE.
func NewFGUserPlaneNode(mac net.HardwareAddr) *IE {
	if mac == nil {
		return New(FGUserPlaneNode, []byte{0x00})
	}

	b := make([]byte, 7)
	b[0] = 0x01
	copy(b[1:7], mac)
	return New(FGUserPlaneNode, b)
}

// HasMAC reports whether an IE has MAC bit.
func (i *IE) HasMAC() bool {
	switch i.Type {
	case FGUserPlaneNode:
		return has1stBit(i.Payload[0])
	default:
		return false
	}
}

// FGUserPlaneNode returns FGUserPlaneNode in net.HardwareAddr if the type of IE matches.
func (i *IE) FGUserPlaneNode() (net.HardwareAddr, error) {
	if len(i.Payload) < 1 {
		return nil, io.ErrUnexpectedEOF
	}

	switch i.Type {
	case FGUserPlaneNode:
		if has1stBit(i.Payload[0]) {
			if len(i.Payload) < 7 {
				return nil, io.ErrUnexpectedEOF
			}
			return net.HardwareAddr(i.Payload[1:7]), nil
		}
		return nil, nil
	case CreatedBridgeInfoForTSC:
		ies, err := i.CreatedBridgeInfoForTSC()
		if err != nil {
			return nil, err
		}
		for _, x := range ies {
			if x.Type == FGUserPlaneNode {
				return x.FGUserPlaneNode()
			}
		}
		return nil, ErrIENotFound
	default:
		return nil, &InvalidTypeError{Type: i.Type}
	}
}
