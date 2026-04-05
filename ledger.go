package ledger

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/bearsh/hid"
	"go.sia.tech/core/types"
)

const (
	appName = "Sia"

	ledgerVendorID  = 0x2c97
	ledgerUsagePage = 0xFFA0

	codeSuccess      = 0x9000
	codeUserRejected = 0x6985
	codeInvalidParam = 0x6b01

	cmdGetVersion    = 0x01
	cmdGetPublicKey  = 0x02
	cmdSignHash      = 0x04
	cmdCalcTxnHash   = 0x08
	cmdCalcV2TxnHash = 0x10

	p1First = 0x00
	p1More  = 0x80

	p2DisplayAddress = 0x00
	p2DisplayPubkey  = 0x01
	p2DisplayHash    = 0x00
	p2SignHash       = 0x01
)

var (
	errUserRejected = errors.New("user denied request")
	errInvalidParam = errors.New("invalid request parameters")
)

type apduExchanger interface {
	Exchange(apdu apdu) ([]byte, error)
}

type apdu struct {
	CLA     byte
	INS     byte
	P1, P2  byte
	Payload []byte
}

func (apdu *apdu) Encode() []byte {
	return append([]byte{apdu.CLA, apdu.INS, apdu.P1, apdu.P2, byte(len(apdu.Payload))}, apdu.Payload...)
}

type hidFramer struct {
	rw  io.ReadWriter
	seq uint16
	buf [64]byte
	pos int
}

func (hf *hidFramer) Reset() {
	hf.seq = 0
}

func (hf *hidFramer) Write(p []byte) (int, error) {
	// split into 64-byte chunks
	chunk := make([]byte, 64)
	binary.BigEndian.PutUint16(chunk[:2], 0x0101)
	chunk[2] = 0x05
	var seq uint16
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, uint16(len(p)))
	buf.Write(p)
	for buf.Len() > 0 {
		binary.BigEndian.PutUint16(chunk[3:5], seq)
		n, _ := buf.Read(chunk[5:])
		if n, err := hf.rw.Write(chunk[:5+n]); err != nil {
			return n, err
		}
		seq++
	}
	return len(p), nil
}

func (hf *hidFramer) Read(p []byte) (int, error) {
	if hf.seq > 0 && hf.pos != 64 {
		// drain buf
		n := copy(p, hf.buf[hf.pos:])
		hf.pos += n
		return n, nil
	}
	// read next 64-byte packet
	if n, err := hf.rw.Read(hf.buf[:]); err != nil {
		return 0, err
	} else if n != 64 {
		panic("read less than 64 bytes from HID")
	}
	// parse header
	channelID := binary.BigEndian.Uint16(hf.buf[:2])
	commandTag := hf.buf[2]
	seq := binary.BigEndian.Uint16(hf.buf[3:5])
	if channelID != 0x0101 {
		return 0, fmt.Errorf("bad channel ID 0x%x", channelID)
	} else if commandTag != 0x05 {
		return 0, fmt.Errorf("bad command tag 0x%x", commandTag)
	} else if seq != hf.seq {
		return 0, fmt.Errorf("bad sequence number %v (expected %v)", seq, hf.seq)
	}
	hf.seq++
	// start filling p
	n := copy(p, hf.buf[5:])
	hf.pos = 5 + n
	return n, nil
}

type apduFramer struct {
	hf  *hidFramer
	buf [2]byte // to read apdu length prefix
}

func (af *apduFramer) Exchange(apdu apdu) ([]byte, error) {
	if len(apdu.Payload) > 255 {
		panic("apdu payload cannot exceed 255 bytes")
	}
	af.hf.Reset()
	if _, err := af.hf.Write(apdu.Encode()); err != nil {
		return nil, err
	}

	// read apdu length
	if _, err := io.ReadFull(af.hf, af.buf[:]); err != nil {
		return nil, err
	}
	// read apdu payload
	respLen := binary.BigEndian.Uint16(af.buf[:])
	resp := make([]byte, respLen)
	_, err := io.ReadFull(af.hf, resp)
	return resp, err
}

type tcpExchanger struct {
	conn net.Conn
	buf  [4]byte
}

func (e *tcpExchanger) Exchange(apdu apdu) ([]byte, error) {
	encoded := apdu.Encode()

	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(encoded)))
	if _, err := e.conn.Write(lenBuf[:]); err != nil {
		return nil, err
	}
	if _, err := e.conn.Write(encoded); err != nil {
		return nil, err
	} else if _, err := io.ReadFull(e.conn, e.buf[:]); err != nil {
		return nil, err
	}
	respLen := int(binary.BigEndian.Uint32(e.buf[:]) + 2)
	resp := make([]byte, respLen)
	_, err := io.ReadFull(e.conn, resp)
	return resp, err
}

type errCode uint16

func (c errCode) Error() string {
	return fmt.Sprintf("Error code 0x%x", uint16(c))
}

// A Device is a connection to a Ledger hardware wallet running the Sia app.
type Device struct {
	ex     apduExchanger
	closer io.Closer
}

func (n *Device) exchangeTxnHash(op byte, data []byte, p2 byte, sigIndex uint16, keyIndex, changeIndex uint32) (resp []byte, err error) {
	buf := bytes.NewBuffer(nil)
	binary.Write(buf, binary.LittleEndian, keyIndex)
	binary.Write(buf, binary.LittleEndian, sigIndex)
	binary.Write(buf, binary.LittleEndian, changeIndex)
	buf.Write(data)

	for buf.Len() > 0 {
		var p1 byte = p1More
		if resp == nil {
			p1 = p1First
		}
		resp, err = n.exchange(op, p1, p2, buf.Next(255))
		if err != nil {
			return nil, err
		}
	}
	return
}

// Close closes the connection to the device.
func (n *Device) Close() error {
	if n.closer != nil {
		return n.closer.Close()
	}
	return nil
}

func (n *Device) exchange(cmd byte, p1, p2 byte, data []byte) (resp []byte, err error) {
	resp, err = n.ex.Exchange(apdu{
		CLA:     0xe0,
		INS:     cmd,
		P1:      p1,
		P2:      p2,
		Payload: data,
	})
	if err != nil {
		return nil, err
	} else if len(resp) < 2 {
		return nil, errors.New("apdu response missing status code")
	}
	code := binary.BigEndian.Uint16(resp[len(resp)-2:])
	resp = resp[:len(resp)-2]
	switch code {
	case codeSuccess:
		err = nil
	case codeUserRejected:
		err = errUserRejected
	case codeInvalidParam:
		err = errInvalidParam
	default:
		err = errCode(code)
	}
	return
}

// GetVersion returns the version of the Sia app running on the device.
func (n *Device) GetVersion() (version string, err error) {
	resp, err := n.exchange(cmdGetVersion, 0, 0, nil)
	if err != nil {
		return "", err
	} else if len(resp) != 3 {
		return "", errors.New("version has wrong length")
	}
	return fmt.Sprintf("v%d.%d.%d", resp[0], resp[1], resp[2]), nil
}

// GetPublicKey returns the public key at the given BIP-44 index.
func (n *Device) GetPublicKey(index uint32) (pubkey types.PublicKey, err error) {
	encIndex := make([]byte, 4)
	binary.LittleEndian.PutUint32(encIndex, index)

	resp, err := n.exchange(cmdGetPublicKey, 0, p2DisplayPubkey, encIndex)
	if err != nil {
		return types.PublicKey{}, err
	}
	if copy(pubkey[:], resp) != len(pubkey) {
		return types.PublicKey{}, errors.New("pubkey has wrong length")
	}
	return
}

// GetAddress returns the address for the public key at the given BIP-44 index.
// The address is displayed on the device for verification.
func (n *Device) GetAddress(index uint32) (addr types.Address, err error) {
	encIndex := make([]byte, 4)
	binary.LittleEndian.PutUint32(encIndex, index)

	resp, err := n.exchange(cmdGetPublicKey, 0, p2DisplayAddress, encIndex)
	if err != nil {
		return types.Address{}, err
	}
	err = addr.UnmarshalText(resp[32:])
	return
}

// SignHash signs a 256-bit hash using the private key at the given index.
func (n *Device) SignHash(hash [32]byte, keyIndex uint32) (sig types.Signature, err error) {
	encIndex := make([]byte, 4)
	binary.LittleEndian.PutUint32(encIndex, keyIndex)

	resp, err := n.exchange(cmdSignHash, 0, 0, append(encIndex, hash[:]...))
	if err != nil {
		return types.Signature{}, err
	}
	if copy(sig[:], resp) != len(sig) {
		return types.Signature{}, errors.New("signature has wrong length")
	}
	return
}

// CalcTxnHash calculates the hash of a v1 transaction on the device and
// displays it for verification.
func (n *Device) CalcTxnHash(txn types.Transaction, sigIndex uint16, changeIndex uint32) (hash types.Hash256, err error) {
	data, err := encodeTxn(txn)
	if err != nil {
		return types.Hash256{}, err
	}
	resp, err := n.exchangeTxnHash(cmdCalcTxnHash, data, p2DisplayHash, sigIndex, 0, changeIndex)
	if err != nil {
		return types.Hash256{}, err
	}
	if copy(hash[:], resp) != len(hash) {
		return types.Hash256{}, errors.New("hash has wrong length")
	}
	return
}

// SignTxn calculates the hash of a v1 transaction on the device and signs it
// using the private key at the given index.
func (n *Device) SignTxn(txn types.Transaction, sigIndex uint16, keyIndex, changeIndex uint32) (sig types.Signature, err error) {
	data, err := encodeTxn(txn)
	if err != nil {
		return types.Signature{}, err
	}
	resp, err := n.exchangeTxnHash(cmdCalcTxnHash, data, p2SignHash, sigIndex, keyIndex, changeIndex)
	if err != nil {
		return types.Signature{}, err
	}
	if copy(sig[:], resp) != len(sig) {
		return types.Signature{}, errors.New("signature has wrong length")
	}
	return
}

// CalcV2TxnHash calculates the hash of a v2 transaction on the device and
// displays it for verification.
func (n *Device) CalcV2TxnHash(txn types.V2Transaction, sigIndex uint16, changeIndex uint32) (hash types.Hash256, err error) {
	data, err := encodeV2Txn(txn)
	if err != nil {
		return types.Hash256{}, err
	}
	resp, err := n.exchangeTxnHash(cmdCalcV2TxnHash, data, p2DisplayHash, sigIndex, 0, changeIndex)
	if err != nil {
		return types.Hash256{}, err
	}
	if copy(hash[:], resp) != len(hash) {
		return types.Hash256{}, errors.New("hash has wrong length")
	}
	return
}

// SignV2Txn calculates the hash of a v2 transaction on the device and signs it
// using the private key at the given index.
func (n *Device) SignV2Txn(txn types.V2Transaction, sigIndex uint16, keyIndex, changeIndex uint32) (sig types.Signature, err error) {
	data, err := encodeV2Txn(txn)
	if err != nil {
		return types.Signature{}, err
	}
	resp, err := n.exchangeTxnHash(cmdCalcV2TxnHash, data, p2SignHash, sigIndex, keyIndex, changeIndex)
	if err != nil {
		return types.Signature{}, err
	}
	if copy(sig[:], resp) != len(sig) {
		return types.Signature{}, errors.New("signature has wrong length")
	}
	return
}

func encodeTxn(txn types.Transaction) ([]byte, error) {
	var buf bytes.Buffer
	enc := types.NewEncoder(&buf)
	txn.EncodeTo(enc)
	if err := enc.Flush(); err != nil {
		return nil, fmt.Errorf("couldn't encode transaction: %w", err)
	}
	return buf.Bytes(), nil
}

func encodeV2Txn(txn types.V2Transaction) ([]byte, error) {
	var buf bytes.Buffer
	enc := types.NewEncoder(&buf)
	types.V2TransactionSemantics(txn).EncodeTo(enc)
	if err := enc.Flush(); err != nil {
		return nil, fmt.Errorf("couldn't encode v2 transaction: %w", err)
	}
	return buf.Bytes(), nil
}

func enumerate() (string, error) {
	devices := hid.Enumerate(ledgerVendorID, 0)
	for _, d := range devices {
		if d.UsagePage == ledgerUsagePage {
			return d.Path, nil
		}
	}
	return "", errors.New("device not detected")
}

func openDevice(path string) (*Device, error) {
	devices := hid.Enumerate(ledgerVendorID, 0)
	for _, d := range devices {
		if d.Path != path {
			continue
		}
		device, err := d.Open()
		if err != nil {
			return nil, err
		}
		return &Device{
			ex: &apduFramer{
				hf: &hidFramer{
					rw: device,
				},
			},
			closer: device,
		}, nil
	}
	return nil, errors.New("device not found")
}

func openApp(path string) error {
	n, err := openDevice(path)
	if err != nil {
		return err
	}
	defer n.Close()
	n.ex.Exchange(apdu{
		CLA:     0xE0,
		INS:     0xD8,
		P1:      0x00,
		P2:      0x00,
		Payload: []byte(appName),
	})
	return nil
}

// Open finds a Ledger device, ensures the Sia app is running, and returns a
// connected Device instance.
func Open() (*Device, error) {
	path, err := enumerate()
	if err != nil {
		return nil, err
	}

	n, err := openDevice(path)
	if err != nil {
		return nil, err
	}

	// if the Sia app is already running, return immediately
	if _, err := n.GetVersion(); err == nil {
		return n, nil
	}
	n.Close()

	// open the Sia app; the device disconnects and reconnects
	if err := openApp(path); err != nil {
		return nil, fmt.Errorf("failed to open Sia app: %w", err)
	}

	// poll for the device to reappear
	for range 10 {
		time.Sleep(500 * time.Millisecond)

		n, err = openDevice(path)
		if err != nil {
			continue
		}
		if _, err := n.GetVersion(); err == nil {
			return n, nil
		}
		n.Close()
	}
	return nil, errors.New("Sia app did not become ready")
}

// OpenTCP connects to a Ledger device over TCP at the given address.
//
// This is intended for testing with a Ledger emulator
func OpenTCP(addr string) (*Device, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	return &Device{
		ex: &tcpExchanger{
			conn: conn,
		},
		closer: conn,
	}, nil
}
