package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"encoding/json"
	"io/ioutil"
	"log"
)

const (
	dle = 0x10
	stx = 0x02
	etx = 0x03
)

func main() {

	// Address of remote endpoint
	serverAddress := "hostname.planefinder.net:80"

	// Construct authentication credentials
	loginJSON := "{\"username\":\"USER\",\"password\":\"PASS\"}\n"

	// Example config, can skip SSL verification but not recommended!
	conf := &tls.Config{
		InsecureSkipVerify: true,
	}

	// Connect to the remote server
	conn, err := tls.Dial("tcp", serverAddress, conf)
	if err != nil {
		log.Println(err)
		return
	}
	defer conn.Close()

	// Send the authentication payload
	// Client will be disconnected if wrong details are sent
	n, err := conn.Write([]byte(loginJSON))
	if err != nil {
		log.Println(n, err)
		return
	}

	reader := bufio.NewReader(conn)
	clientBuffer := new(bytes.Buffer)

	for {
		// Read a byte
		byte, err := reader.ReadByte()

		if err != nil {
			conn.Close()
			return
		}

		// Write the byte to a buffer
		wrErr := clientBuffer.WriteByte(byte)
		if wrErr != nil {
			log.Println("Write Error:", wrErr)
		}

		// Check to see if we now have a valid packet in the buffer
		packet := popPacketFromBuffer(clientBuffer)
		if packet != nil {

			// Buffer had a packet so place into a new buffer for decompression.
			packetBuffer := bytes.NewBuffer(packet)

			// Decompress the packet
			jsonData, err := uncompress(packetBuffer.Bytes())
			if err != nil {
				log.Println("Unzip Error:", err)
			} else {
				// json will contain the json that needs parsing/processing
				// Suggest processing on different thread to not hold this up!
				//log.Println(string(json))
				var dat map[string]interface{}

				if err := json.Unmarshal(jsonData, &dat); err != nil {
					panic(err)
				}

				for key, value := range dat {
					mapData := value.(map[string]interface{})
					callsign, _ := mapData["callsign"]
					reg, _ := mapData["reg"]
					lat, _ := mapData["lat"]
					lon, _ := mapData["lon"]
					log.Println(key, reg, callsign, lat, lon)
				}
			}
		}
	}
}

func popPacketFromBuffer(buffer *bytes.Buffer) []byte {

	bufferLength := buffer.Len()

	if bufferLength >= 750000 {
		log.Println("Buffer is too large ", bufferLength)
		buffer.Reset()
		return nil
	}

	tempBuffer := buffer.Bytes()
	length := len(tempBuffer)

	// Return on small packet length
	if length < 3 {
		return nil
	}

	if (tempBuffer[length-2] == dle) && (tempBuffer[length-1] == etx) {

		dleCount := 0
		for i := range tempBuffer {
			// Skip the first one!
			if i == 0 {
				continue
			}
			if tempBuffer[len(tempBuffer)-1-i] == dle {
				dleCount += 1
			} else {
				break
			}
		}

		isEven := dleCount%2 == 0

		// If this is even then this is not the end but a byte stuffed DLE packet
		if isEven == true {
			return nil
		}

		// Grab the contents of the provided packet
		extractedPacket := buffer.Bytes()

		// Clear the main buffer now we have extracted a packet from it
		buffer.Reset()

		// Ensure packet begins with a valid startDelimiter
		if extractedPacket[0] != dle && extractedPacket[1] != stx {
			log.Println("Popped a packet without a valid start delimiter", extractedPacket)
			return nil
		}

		// Remove the start and end caps
		slice := extractedPacket[2 : len(extractedPacket)-2]

		return deStuffPacket(slice)
	}

	return nil
}

// Removes duplicate delimiters from the packet
func deStuffPacket(packet []byte) []byte {

	lengthOfPacket := len(packet)

	newByteArray := new(bytes.Buffer)

	for i := 0; i < lengthOfPacket; i++ {
		if packet[i] == dle && packet[i+1] == dle {
			newByteArray.WriteByte(packet[i])
			i++
		} else {
			newByteArray.WriteByte(packet[i])
		}
	}

	return newByteArray.Bytes()
}

// Uses gzip to uncompress the packet
// Packet should already be destuffed
func uncompress(packet []byte) ([]byte, error) {
	r, gzErr := gzip.NewReader(bytes.NewBuffer(packet))
	if gzErr != nil {
		log.Println("Gzip Error:", gzErr)
		blankBytes := []byte{}
		return blankBytes, gzErr
	}
	defer r.Close()

	bytesRead, err := ioutil.ReadAll(r)
	if err != nil {
		log.Println(err)
	}
	return bytesRead, err
}
