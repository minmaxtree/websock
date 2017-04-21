package websock

import (
    "fmt"
    "net/http"
    "crypto/sha1"
    "encoding/base64"
    "net"
    "errors"
    "bufio"
    "strings"
    "encoding/binary"
    "io"
    "math/rand"
    "unicode/utf8"
)

const (
    ContinuationFrame = 0
    TextFrame = 1
    BinaryFrame = 2
    ConnectionCloseFrame = 8
    PingFrame = 9
    PongFrame = 10
)

const (
    TextMessage = 11
    BinaryMessage = 12
    PingMessage = 13
    PongMessage = 14
)

type BaseFrame struct {
    fin byte    // 1 bit
    reserved byte    // 3 bits
    opcode byte    // 4 bits
    mask byte    // 1 bit
    payloadLen uint64    // 7 bits / 7 + 16 bits / 7 + 64 bits
    maskingKey []byte    // 0 or 4 bytes
    payload []byte
}

var listenPort = 8200

type Upgrader struct {
    ReadBufferSize int
    WriteBufferSize int
}

func (upgrader *Upgrader)Upgrade(w http.ResponseWriter, r *http.Request) (Conn, error) {
    upgrade := r.Header.Get("Upgrade")
    fmt.Println("Upgrade is:", upgrade)
    if strings.ToLower(upgrade) == "websocket" {
        secWebSocketKey := r.Header.Get("Sec-WebSocket-Key")
        secWebSocketAccept := calcSecWebSocketAccept(secWebSocketKey)
        hj, ok := w.(http.Hijacker)
        if !ok {
            http.Error(w, "hijacking not supported", http.StatusInternalServerError)
            return Conn {}, errors.New("hijacking not supported")
        }

        conn, bufrw, err := hj.Hijack()
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return Conn {}, errors.New("hijacking failed")
        }

        bufrw.WriteString("HTTP/1.1 101 Switching Protocols\r\n")
        bufrw.WriteString("Upgrade: websocket\r\n")
        bufrw.WriteString("Connection: Upgrade\r\n")
        bufrw.WriteString("Sec-WebSocket-Accept: " + secWebSocketAccept + "\r\n")
        bufrw.WriteString("\r\n")
        bufrw.Flush()

        newConn := Conn {
            Conn: conn,
            ReadBufferSize: upgrader.ReadBufferSize,
            WriteBufferSize : upgrader.WriteBufferSize,
            isServer: true,
        }

        return newConn, nil
    } else {
        return Conn {}, errors.New("No client connecting")
    }
}

type Dialer struct {
    ReaderBufferSize int
    WriteBufferSize int
}

func (dialer *Dialer)Dial(url string) (Conn, error) {
    ps := strings.SplitN(url, "/", 2)
    conn, err := net.Dial("tcp", ps[0])
    if err != nil {
        return Conn {}, err
    }

    httpHeaders := [][]string {
        { "Host", "localhost:8200" },
        { "Upgrade", "websocket" },
        { "Sec-WebSocket-Version", "13" },
        { "Sec-WebSocket-Key", "MgGOmPMgJj2AdesykTNMvA==" },
        { "Connection", "Upgrade" },
    }

    buf := fmt.Sprintf("GET %s HTTP/1.1\r\n", "/" + ps[1])
    for _, header := range httpHeaders {
        buf += header[0] + ": " + header[1] + "\r\n"
    }
    buf += "\r\n"

    conn.Write([]byte(buf))

    reader := bufio.NewReader(conn)

    for {
        line, err := reader.ReadString('\n')
        if err != nil {
            return Conn {}, err
        }
        if line == "\r\n" {
            break
        }
    }

    return Conn {
        Conn: conn,
        ReadBufferSize: dialer.ReaderBufferSize,
        WriteBufferSize: dialer.WriteBufferSize,
        isServer: false,
    }, nil
}

type Conn struct {
    Conn net.Conn
    ReadBufferSize int
    WriteBufferSize int
    isServer bool
    unreadPayloadLen int
    unreadPayloadType int
    frame BaseFrame
    eof bool
}

type MessageReader struct {
    offs int
    unread int
    eof bool
    buf []byte
}

type MessageWriteCloser struct {
    conn net.Conn
    messageType int
    mask bool
}

func NewMessageReader(unread int, buf []byte) *MessageReader {
    ret := new(MessageReader)
    ret.unread = unread
    ret.buf = buf
    return ret
}

func NewMessageWriteCloser(conn net.Conn, messageType int, mask bool) *MessageWriteCloser{
    ret := new(MessageWriteCloser)
    ret.conn = conn
    ret.messageType = messageType
    ret.mask = mask
    return ret
}

func (messageReader *MessageReader)Read(p []byte) (int, error) {
    if messageReader.eof {
        return 0, io.EOF
    }
    var n int
    if len(p) >= messageReader.unread {
        n = messageReader.unread
    } else {
        n = len(p)
    }
    buf := messageReader.buf[messageReader.offs:messageReader.offs+n]
    for i := range(buf) {
        p[i] = buf[i]
    }
    messageReader.offs += n
    messageReader.unread -= n
    if messageReader.unread == 0 {
        messageReader.eof = true
    }
    return n, nil
}

func (messageWriteCloser *MessageWriteCloser)Write(p []byte) (n int, err error) {
    header := make([]byte, 2)

    fin := 1
    var opcode byte
    if messageWriteCloser.messageType == TextMessage {
        opcode = TextFrame
    } else if messageWriteCloser.messageType == BinaryMessage {
        opcode = BinaryFrame
    }
    header[0] = byte(fin << 7) + opcode

    if messageWriteCloser.mask {
        header[1] += 1 << 7
    }
    if len(p) < 126 {
        header[1] += byte(len(p))
    } else if len(p) <= 0xffff {
        header[1] += 126
        buf := make([]byte, 2)
        binary.BigEndian.PutUint16(buf, uint16(len(p)))
        header = append(header, buf...)
    } else {
        header[1] += 127
        buf := make([]byte, 8)
        binary.BigEndian.PutUint64(buf, uint64(len(p)))
        header = append(header, buf...)
    }

    payload := p
    if messageWriteCloser.mask {
        maskingKey := make([]byte, 4)
        for i := range maskingKey {
            maskingKey[i] = byte(rand.Int())
        }
        header = append(header, maskingKey...)

        for i := range p {
            payload[i] = p[i] ^ maskingKey[i % 4]
        }
    }

    frame := append(header, payload...)
    messageWriteCloser.conn.Write(frame)
    return len(p), nil
}

func (messageWriteCloser MessageWriteCloser)Close() error {
    return nil
}

type WebSocketHeader struct {
    fin byte
    opcode byte
    mask byte
    payloadLen uint64
    maskingKey []byte
}

func newWebSocketHeader(fin byte, opcode byte, mask byte, payloadLen uint64,
        maskingKey []byte) *WebSocketHeader {
    ret := new(WebSocketHeader)
    ret.fin = fin
    ret.opcode = opcode
    ret.mask = mask
    ret.payloadLen = payloadLen
    ret.maskingKey = maskingKey
    return ret
}

func isKnownOpcode(opcode byte) bool {
    return (opcode == ContinuationFrame) ||
           (opcode == TextFrame) ||
           (opcode == BinaryFrame) ||
           (opcode == ConnectionCloseFrame) ||
           (opcode == PingFrame) ||
           (opcode == PongFrame)
}

func readWebSocketHeader(reader net.Conn) (*WebSocketHeader, error) {
    buf := make([]byte, 2)
    offs := 0
    for offs < 2 {
        n, err := reader.Read(buf[offs:])
        if err != nil {
            return nil, err
        }
        offs += n
    }

    fin := (buf[0] >> 7) & 1
    rsv := (buf[0] >> 4) & 7
    // if no extensions negotiated, rsv should be 0,
    // otherwise close the connection
    if rsv != 0 {
        closeConnection(reader)
        return nil, CONNECTION_CLOSED
    }
    opcode := buf[0] & 0xf
    // if an unknwon opcode is received, the receiving
    // endpoint must fail the connection
    if !isKnownOpcode(opcode) {
        closeConnection(reader)
        return nil, CONNECTION_CLOSED
    }
    mask := (buf[1] >> 7) & 1
    var payloadLen uint64 = uint64(buf[1] &0x7f)
    if payloadLen == 126 {
        buf = make([]byte, 2)
        _, err := reader.Read(buf)
        if err != nil {
            return nil, err
        }
        payloadLen = uint64(binary.BigEndian.Uint16(buf))
    } else if payloadLen == 127 {
        buf = make([]byte, 8)
        _, err := reader.Read(buf)
        if err != nil {
            return nil, err
        }
        payloadLen = binary.BigEndian.Uint64(buf)
    }
    maskingKey := make([]byte, 4)
    if mask == 1 {
        offs := 0
        for offs < 4 {
            n, err := reader.Read(maskingKey[offs:])
            if err != nil {
                return nil, err
            }
            offs += n
        }
    }
    return newWebSocketHeader(fin, opcode, mask, payloadLen, maskingKey), nil
}

var CONNECTION_CLOSED error = errors.New("WebSock: Connection Closed")

func closeConnection(conn net.Conn) {
    closeFrame := make([]byte, 2)
    fin := 1
    closeFrame[0] = byte(fin << 7) + ConnectionCloseFrame
    closeFrame[1] = 0  // no mask, no data
    _, err := conn.Write(closeFrame)
    check(err)
    conn.Close()
}

func (conn *Conn)NextReader() (int, io.Reader, error) {
    var frameHeader *WebSocketHeader
    var err error

    dataBuf := []byte {}

    var messageType int

    isFirstFragment := true

    for {
        for {
            frameHeader, err = readWebSocketHeader(conn.Conn)
            if err != nil {
                return 0, nil, err
            }
            if frameHeader.opcode == PingFrame {
                if frameHeader.fin == 0 {
                    closeConnection(conn.Conn)
                    return 0, nil, CONNECTION_CLOSED
                }
                if frameHeader.payloadLen > 125 {
                    closeConnection(conn.Conn)
                    return 0, nil, CONNECTION_CLOSED
                }
                payload := make([]byte, frameHeader.payloadLen)
                offs := 0
                for offs < len(payload) {
                    n, err := conn.Conn.Read(payload[offs:])
                    check(err)
                    offs += n
                }
                check(err)
                pongFrameHeader := make([]byte, 2)
                pongFrameHeader[0] = byte(1 << 7) + PongFrame
                pongFrameHeader[1] = byte(frameHeader.payloadLen)  // no mask, same payload
                if frameHeader.mask != 0 {
                    for i := range payload {
                        payload[i] = payload[i] ^ frameHeader.maskingKey[i % 4]
                    }
                }
                fmt.Println("payload is:", payload)
                pongFrame := append(pongFrameHeader, payload...)
                conn.Conn.Write(pongFrame)
            } else if frameHeader.opcode == PongFrame {
                if frameHeader.fin == 0 {
                    closeConnection(conn.Conn)
                    return 0, nil, CONNECTION_CLOSED
                }
                // for now, assume unsolicited pong, ignore
                offs := 0
                buf := make([]byte, frameHeader.payloadLen)
                for offs < len(buf) {
                    n, err := conn.Conn.Read(buf[offs:])
                    check(err)
                    offs += n
                }
            } else {
                break
            }
        }

        if frameHeader.opcode == ConnectionCloseFrame {
            closeFrame := make([]byte, 2)
            fin := 1
            closeFrame[0] = byte(fin << 7) + ConnectionCloseFrame
            closeFrame[1] = 0  // no mask, no data
            _, err := conn.Conn.Write(closeFrame)
            if err != nil {
                return 0, nil, err
            }
            conn.Conn.Close()
            return 0, nil, CONNECTION_CLOSED
        }

        if isFirstFragment && frameHeader.opcode == 0 {
            closeConnection(conn.Conn)
            return 0, nil, CONNECTION_CLOSED
        }
        if !isFirstFragment && frameHeader.opcode != 0 {
            closeConnection(conn.Conn)
            return 0, nil, CONNECTION_CLOSED
        }

        if frameHeader.opcode == TextFrame {
            messageType = TextMessage
        } else if frameHeader.opcode == BinaryFrame {
            messageType = BinaryMessage
        }

        buf := make([]byte, frameHeader.payloadLen)
        offs := 0
        for offs < len(buf) {
            n, err := conn.Conn.Read(buf[offs:])
            if err != nil {
                return 0, nil, err
            }
            offs += n
        }
        if frameHeader.mask == 1 {
            for i := range buf {
                buf[i] = buf[i] ^ frameHeader.maskingKey[i % 4]
            }
        }

        dataBuf = append(dataBuf, buf...)

        if frameHeader.fin == 1 {
            break
        }

        isFirstFragment = false
    }

    if messageType == TextMessage {
        if !utf8.Valid(dataBuf) {
            closeConnection(conn.Conn)
            return 0, nil, CONNECTION_CLOSED
        }
    }

    return messageType, NewMessageReader(len(dataBuf), dataBuf), nil
}

func (conn *Conn)NextWriter(messageType int) (io.WriteCloser, error) {
    var mask bool
    if conn.isServer {
        mask = false
    } else {
        mask = true
    }
    return NewMessageWriteCloser(conn.Conn, messageType, mask), nil
}

func calcSecWebSocketAccept(secWebSocketKey string) string {
    appended := secWebSocketKey + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    h := sha1.New()
    h.Write([]byte(appended))
    hashed := h.Sum(nil)
    return base64.StdEncoding.EncodeToString(hashed)
}

func check(err error) {
    if err != nil {
        panic(err)
    }
}
