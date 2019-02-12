tls = require('tls');
zlib = require("zlib");

let dle = 0x10;
let stx = 0x02;
let etx = 0x03;

var credentials = {"username":"USER","password":"PASS"};
var credentialsString = JSON.stringify(credentials)

// callback for when secure connection established
function connected(stream) {
    if (stream) {
        // socket connected
        stream.write(credentialsString + "\r\n");
    } else {
        console.log("Connection failed");
    }
}

// needed to keep socket variable in scope
var tcpSock = this;

// declare a blank buffer
tcpSock.buffer = null;

// try to connect to the server
tcpSock.socket = tls.connect(80, 'hostname.planefinder.net', function() {
    // callback called only after successful socket connection
    tcpSock.connected = true;
    if (tcpSock.socket.authorized) {
        // authorization successful
        connected(tcpSock.socket);
    } else {
        // authorization failed
        console.log(tcpSock.socket.authorizationError);
        connected(null);
    }
});


tcpSock.socket.on("data",function (data) {
    // Add our data to the packet buffer
    tcpSock.buffer = tcpSock.buffer != null ? Buffer.concat([tcpSock.buffer, data]) : data;

    // Attempt to pop all packets from buffer
    var packet = null;

    // Attempt to see if the buffer contains a valid packet yet
    while((packet = tcpSock.popFromBuffer()) != null)
    {
        // decompress the payload
        zlib.gunzip(packet, function(err, decoded) {
        if(!err)
        {
            //valid json, needs parsing and processing from here
            var planes = JSON.parse(decoded);
            var planeCount = Object.keys(planes).length;
            console.log("Decoded", planeCount,"planes from payload");
            //console.log(planes);
        }
        else
        {
            console.log("Failed to decode packet");
        }
        });
    }
});

tcpSock.socket.addListener('error', function(error) {
    if (!tcpSock.connected) {
        // socket was not connected, notify callback
        connected(null);
    }
    console.log("FAIL");
    console.log(error);
});

tcpSock.socket.addListener('close', function() {
    // do something
});

// Removes duplicate delimiters from the packet
tcpSock.deStuff = function(packet) {
    var buffer = new Buffer(packet.length);
    var o = 0;
    for(var i = 0; i < packet.length; i++, o++)
    {
        if(packet[i] == dle && packet[i+1] == dle)
        {
            buffer[o] = packet[i];
            i++;
        }
        else 
        {
            buffer[o] = packet[i];
        }
    }

    // Readjust the size of our destuffed packet to avoid garbage on the end
    return buffer.slice(0, o);
}

// Attempts to find whole packets within a buffer
tcpSock.popFromBuffer = function () {
    if(tcpSock.buffer == null) return null;

    // Determine the EOP (end of packet) position by looking for an instance of our delimiter
    var EOP = -1;
    for(var i = 0; i < tcpSock.buffer.length-1; i++)
    {
        if(tcpSock.buffer[i] == dle)
        {
            if(tcpSock.buffer[i+1] == dle)
            {
                i++;
            }
            else if (tcpSock.buffer[i+1] == etx)
            {
                // We found a single delimiter, so consider this the end of a packet
                EOP = i;
                break;
            }
        }
    }

    if(EOP != -1)
    {
        // Grab the contents of the provided packet
        var packet = tcpSock.buffer.slice(0, EOP);

        // Pop the contents of our packet off of the contents buffer,
        // and be sure to reset it to NULL if it's now empty
        if(EOP+2 < tcpSock.buffer.length)
        {
            tcpSock.buffer = tcpSock.buffer.slice(EOP+2, tcpSock.buffer.length);
        }
        else
        {
            tcpSock.buffer = null;
        }

        // Ensure our packet has a valid start delimiter
        if(packet[0] != dle && packet[0] != stx)
        {
            console.log("Popped a packet without a valid start delimiter");
            return null;
        }

        // De-stuff it		
        packet = packet.slice(2); // ditch the start delimiter
    
        packet = tcpSock.deStuff(packet);
        return packet;
    }

    return null;
}