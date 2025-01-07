package rtrlib

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"

	"golang.org/x/crypto/ssh"
)

type RTRClientSessionEventHandler interface {
	//RequestCache(*ClientSession)
	HandlePDU(*ClientSession, PDU)
	ClientConnected(*ClientSession)
	ClientDisconnected(*ClientSession)
}

type ClientSession struct {
	version uint8

	connected bool
	tcpconn   net.Conn
	rd        io.Reader
	wr        io.Writer

	transmits chan PDU
	quit      chan bool

	handler RTRClientSessionEventHandler

	log Logger
}

type ClientConfiguration struct {
	ProtocolVersion uint8

	RefreshInterval uint32
	RetryInterval   uint32
	ExpireInterval  uint32

	Log Logger
}

func NewClientSession(configuration ClientConfiguration, handler RTRClientSessionEventHandler) *ClientSession {
	return &ClientSession{
		version:   configuration.ProtocolVersion,
		transmits: make(chan PDU, 256),
		quit:      make(chan bool),
		log:       configuration.Log,
		handler:   handler,
	}
}

func (c *ClientSession) SendResetQuery() {
	pdu := &PDUResetQuery{}
	c.SendPDU(pdu)
}

func (c *ClientSession) SendSerialQuery(sessionid uint16, serial uint32) {
	pdu := &PDUSerialQuery{
		SessionId:    sessionid,
		SerialNumber: serial,
	}
	c.SendPDU(pdu)
}

func (c *ClientSession) SendPDU(pdu PDU) {
	pdu.SetVersion(c.version)
	c.SendRawPDU(pdu)
}

func (c *ClientSession) SendRawPDU(pdu PDU) {
	c.transmits <- pdu
}

func (c *ClientSession) sendLoop() {
	for c.connected {
		select {
		case pdu := <-c.transmits:
			if c.wr != nil {
				c.wr.Write(pdu.Bytes())
			}
		case <-c.quit:
			return
		}
	}
}

func (c *ClientSession) Disconnect() {
	c.connected = false
	//log.Debugf("Disconnecting client %v", c.String())
	if c.handler != nil {
		c.handler.ClientDisconnected(c)
	}
	select {
	case c.quit <- true:
	default:

	}

	c.tcpconn.Close()
}

func (c *ClientSession) StartRW(rd io.Reader, wr io.Writer) error {
	go c.sendLoop()
	if c.handler != nil {
		c.handler.ClientConnected(c)
	}
	for c.connected {
		dec, err := Decode(c.rd)
		if err != nil || dec == nil {
			if c.log != nil {
				c.log.Errorf("Error %v", err)
			}
			c.Disconnect()
			return err
		}
		if c.version == PROTOCOL_VERSION_1 && dec.GetVersion() == PROTOCOL_VERSION_0 {
			if c.log != nil {
				c.log.Infof("Downgrading to version 0")
			}
			c.version = PROTOCOL_VERSION_0
		}

		if c.handler != nil {
			c.handler.HandlePDU(c, dec)
		}
	}
	return nil
}

func (c *ClientSession) StartWithConn(tcpconn net.Conn) error {
	c.tcpconn = tcpconn
	c.wr = tcpconn
	c.rd = tcpconn
	c.connected = true

	return c.StartRW(c.tcpconn, c.tcpconn)
}

func (c *ClientSession) StartWithSSH(tcpconn *net.TCPConn, session *ssh.Session) error {
	c.tcpconn = tcpconn
	c.rd, _ = session.StdoutPipe()
	c.wr, _ = session.StdinPipe()
	c.connected = true

	return c.StartRW(c.rd, c.wr)
}

func (c *ClientSession) StartPlain(addr string) error {
	addrTCP, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return err
	}
	tcpconn, err := net.DialTCP("tcp", nil, addrTCP)
	if err != nil {
		return err
	}
	return c.StartWithConn(tcpconn)
}

func (c *ClientSession) StartTLS(addr string, config *tls.Config) error {
	tcpconn, err := tls.Dial("tcp", addr, config)
	if err != nil {
		return err
	}
	return c.StartWithConn(tcpconn)
}

func (c *ClientSession) StartSSH(addr string, config *ssh.ClientConfig) error {
	addrTCP, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return err
	}
	tcpconn, err := net.DialTCP("tcp", nil, addrTCP)
	if err != nil {
		return err
	}

	conn, chans, reqs, err := ssh.NewClientConn(tcpconn, addr, config)
	if err != nil {
		return err
	}

	//client, err := ssh.Dial("tcp", addr, config)
	client := ssh.NewClient(conn, chans, reqs)
	session, err := client.NewSession()
	if err != nil {
		return err
	}
	err = session.RequestSubsystem("rpki-rtr")
	if err != nil {
		return err
	}
	return c.StartWithSSH(tcpconn, session)
}

func (c *ClientSession) Start(addr string, connType int, configTLS *tls.Config, configSSH *ssh.ClientConfig) error {
	switch connType {
	case TYPE_TLS:
		return c.StartTLS(addr, configTLS)
	case TYPE_PLAIN:
		return c.StartPlain(addr)
	case TYPE_SSH:
		return c.StartSSH(addr, configSSH)
	default:
		return fmt.Errorf("unknown ClientSession type %v", connType)
	}
}
