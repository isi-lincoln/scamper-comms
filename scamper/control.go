package scamper

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

var (
	waitDelay     = 5 * time.Second
	buffer    int = 4096
	Format    string
)

func checkOnline(conn net.Conn, logger *logrus.Logger) (bool, error) {
	if logger != nil {
		logger.Debugf("In checkOnline 0")
	}

	msg := []byte("help\n")
	_, err := conn.Write(msg)
	if err != nil {
		return false, err
	}

	// should only recieve a one line response
	recv, err := bufio.NewReader(conn).ReadString('\n')

	helpResponse := "ERR XXX: todo\n"
	resp := string(recv)

	if resp == helpResponse {
		return true, nil
	} else {
		if logger != nil {
			logger.Errorf("should have got: %s, instead got: %s\n", helpResponse, resp)
		}
		return false, nil
	}

	return false, nil
}

// sudo apt-get install sharutils
func decodeUU(uuencoded []byte) ([]byte, error) {
	preamble := []byte("begin 644 cat.txt")
	ending := append(
		append(
			[]byte{uuencoded[0]},
			[]byte("end")...,
		),
		uuencoded[0],
	)
	var x []byte
	x = append(preamble, uuencoded...)
	x = append(x, ending...)
	//log.Infof("x: %s\n", string(x))
	/*
		data, err := uu.Decode(x)
		if err != nil {
			return nil, err
		}
		return data.Data, nil
	*/
	return x, nil
}

func parser(conn net.Conn, resp []byte, logger *logrus.Logger) ([]int, []byte, error) {

	if logger != nil {
		logger.Debugf("in parser\n")
	}

	c := make([]int, 0)
	d := make([]byte, 0)
	asLines := strings.Split(string(resp), "\n")

	expectOK := "OK"     // recvieved
	expectMore := "MORE" // there are additional responses
	expectData := "DATA" // DATA [bytes] [id]

	dCounter := 0
	for l, line := range asLines {
		if logger != nil {
			logger.Debugf("%d: %s\n", l, line)
		}
		if strings.Contains(line, expectOK) {
			sp := strings.Split(line, " ")
			if len(sp) > 1 {
				_ = sp[1] // id
			}
		}
		if strings.Contains(line, expectMore) {
			// for warts we get 2 lines, json only one
			if strings.Contains(Format, "wart") {
				dCounter = dCounter + 1
			}
		}
		if strings.Contains(line, expectData) {
			dCounter = dCounter - 1
			form := strings.Split(line, " ")
			_ = form[0]     // DATA
			strb := form[1] // bytes
			b, err := strconv.Atoi(strb)
			if err != nil {
				return nil, nil, fmt.Errorf("expected DATA INT, got: %s", strb)
			}
			if len(form) > 2 {
				_ = form[2] // id
			}

			if l >= len(asLines) {
				return nil, nil, fmt.Errorf("expected DATA, but nothing after data line: %s", line)
			}

			// set x to current loc
			x := len([]byte(strings.Join(asLines[:l+1], "\n")))

			if logger != nil {
				logger.Debugf("Got: %s\n", resp[x:x+b])
			}

			c = append(c, b)
			var v []byte
			if strings.Contains(Format, "wart") {
				v, err = decodeUU(resp[x : x+b])
				if err != nil {
					return nil, nil, err
				}
			} else {
				v = resp[x : x+b]
			}
			d = append(d, v...)
		}
	}

	if logger != nil {
		logger.Debugf("dCounter: %d\n", dCounter)
	}

	// assumes only 1 MORE
	if dCounter >= 0 {

		if logger != nil {
			logger.Debug("Calling parser again")
		}

		// only call this if we didnt read 2 data
		conn.SetReadDeadline(time.Now().Add(waitDelay))

		// read another message
		recv := make([]byte, buffer)
		m, err := conn.Read(recv)
		if err != nil {
			return nil, nil, err
		}

		t, x, err := parser(conn, recv[:m], logger)
		if err != nil {
			return nil, nil, err
		}
		c = append(c, t...)
		d = append(d, x...)

	}

	return c, d, nil
}

func sendFormattingRequest(conn net.Conn, logger *logrus.Logger) (bool, error) {
	// Send the message "hello"
	msg := []byte(fmt.Sprintf("attach format %s\n", Format))
	if logger != nil {
		logger.Debugf("format: %s", msg)
	}
	_, err := conn.Write(msg)
	if err != nil {
		return false, err
	}
	conn.SetReadDeadline(time.Now().Add(waitDelay))

	// Receive the response
	recv := make([]byte, buffer)
	n, err := conn.Read(recv)
	if err != nil {
		return false, err
	}

	if logger != nil {
		logger.Debugf("recv'd: %s", string(recv[:n]))
	}

	_, _, err = parser(conn, recv[:n], logger)
	if err != nil {
		return false, err
	}

	return true, nil
}

func sendTrace(conn net.Conn, command string, logger *logrus.Logger) (bool, []byte, error) {
	// Send the message "hello"
	msg := []byte(fmt.Sprintf("%s\n", command))

	if logger != nil {
		logger.Debugf("Sending command: %s", msg)
	}

	_, err := conn.Write(msg)
	if err != nil {
		return false, nil, err
	}
	conn.SetReadDeadline(time.Now().Add(waitDelay))

	// Receive the response
	recv := make([]byte, buffer)
	n, err := conn.Read(recv)
	if err != nil {
		return false, nil, err
	}

	x, data, err := parser(conn, recv[:n], logger)
	if err != nil {
		return false, nil, err
	}

	// simplify just return the first
	if len(x) > 1 {

		// scamper returns a newline before the json for some reason
		return true, data[1:x[0]], nil
	}

	return true, data[1:], nil
}

func RequestTrace(addr, command, fiPath, format string, logger *logrus.Logger) (string, error) {

	fields := logrus.Fields{"dst": addr, "command": command, "filepath": fiPath, "format": format}
	if logger != nil {
		logger.WithFields(fields).Debug("in request")
	}
	Format = format
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	ok, err := checkOnline(conn, logger)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", fmt.Errorf("Failed to recieve correct help message")
	}

	if logger != nil {
		logger.WithFields(fields).Debug("scamper control online")
	}

	ok, err = sendFormattingRequest(conn, logger)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", fmt.Errorf("Failed to recieve OK to format message")
	}

	if logger != nil {
		logger.WithFields(fields).Debug("in formatting json")
	}

	ok, warts, err := sendTrace(conn, command, logger)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", fmt.Errorf("Trace message failed at parsing")
	}

	if format == "json" {
		fields["output"] = warts
	}

	if logger != nil {
		logger.WithFields(fields).Debug("finished request")
	}

	if fiPath != "" {
		err = ioutil.WriteFile(fiPath, warts, 0644)
		if err != nil {
			return "", err
		}
	}

	return string(warts), nil
}
