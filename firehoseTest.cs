using System;
using System.Collections.Generic;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;
using System.Security.Cryptography.X509Certificates;
using System.IO;
using System.IO.Compression;

namespace PF_Firehose_Example
{
    public class PF_Firehose_Example
    {
        public const int dle = 0x10;
        public const int stx = 0x02;
        public const int etx = 0x03;

        public static String username = "USER";
        public static String password = "PASS";
        public static String initiation_command = "{\"username\":\"" + username + "\",\"password\":\"" + password + "\"}";

        static void Main(string[] args)
        {
            String serverName = "hostname.planefinder.net";

            PF_Firehose_Example.RunClient(serverName);
            return;
        }

        public static void RunClient(string serverName)
        {
            // Create a TCP/IP client socket.
            TcpClient client = new TcpClient(serverName, 80);

            // Create ssl stream to read data
            SslStream sslStream = new SslStream(
                client.GetStream(),
                true,
                new RemoteCertificateValidationCallback(RemoteCertificateValidationCallback),
                null);
            try
            {
                sslStream.AuthenticateAsClient(serverName);
                Console.WriteLine("sslStream AuthenticateAsClient completed.");
            }
            catch (AuthenticationException e)
            {
                Console.WriteLine("Exception: {0}", e.Message);
                if (e.InnerException != null)
                {
                    Console.WriteLine("Inner exception: {0}", e.InnerException.Message);
                }
                Console.WriteLine("Authentication failed - closing the connection.");
                client.Close();
                return;
            }

            // Send authentication JSON payload command to the server.
            byte[] messsage = Encoding.UTF8.GetBytes(initiation_command + "\n");
            sslStream.Write(messsage);
            sslStream.Flush();

            int lastByteRead;

            var buffer = new List<byte>();
            do
            {
                lastByteRead = sslStream.ReadByte();
                buffer.Add((byte)lastByteRead);

                // If our buffer grows too large truncate it
                if (buffer.Count >= 125000 * 20)
                {
                    buffer.Clear();
                }

                // Attempt to pop a valid packet from the buffer
                var result = PopPacketFromBuffer(buffer);
                if (result != null)
                {
                    var decompressed = Decompress(result.ToArray());
                    string jsonDecompressed = System.Text.Encoding.UTF8.GetString(decompressed);

                    Console.WriteLine("[" + DateTime.Now.ToString() + "]: Successfully decoded JSON packet (length: " + jsonDecompressed.Length + ")");
                    buffer.Clear();
                }
            }
            while (lastByteRead != -1);

            client.Close();
            Console.WriteLine("Client closed.");
        }

        static byte[] Decompress(byte[] data)
        {
            using (var compressedStream = new MemoryStream(data))
            using (var zipStream = new GZipStream(compressedStream, CompressionMode.Decompress))
            using (var resultStream = new MemoryStream())
            {
                zipStream.CopyTo(resultStream);
                return resultStream.ToArray();
            }
        }

        static List<byte> DeStuffPacket(List<byte> stuffedPacket)
        {
            var lengthOfBuffer = stuffedPacket.Count;

            var buffer = new List<byte>();
            for (int i = 0; i < lengthOfBuffer - 1; i++)
            {
                if (stuffedPacket[i] == dle && stuffedPacket[i + 1] == dle)
                {
                    // Write a single DLE byte!
                    buffer.Add(dle);
                    i++;
                }
                else if (stuffedPacket[i] == dle && stuffedPacket[i + 1] == stx)
                {
                    // Skip the header from the framing
                    i++;
                }
                else if (stuffedPacket[i] == dle && stuffedPacket[i + 1] == etx)
                {
                    // Skip the footer from the framing
                    i++;
                }
                else
                {
                    // Write the byte as it's ok!
                    buffer.Add(stuffedPacket[i]);
                }
            }

            return buffer;
        }

        static List<byte> PopPacketFromBuffer(List<byte> buffer)
        {
            var lengthOfBuffer = buffer.Count;

            // Return on small packet length
            if (lengthOfBuffer < 4) return null;

            if (buffer[lengthOfBuffer - 2] == dle && buffer[lengthOfBuffer - 1] == etx){

                // Check to see if we have an odd number of DLE packets
                // An Even number will signify a DLE stuffed mid packet!
                int dleCount = 0;
                for (int i = lengthOfBuffer - 2; i >= 0; i--)
                {
                    if (buffer[i] == dle){
                        dleCount += 1;
                    }else{
                        break;
                    }
                }

                if (dleCount % 2 == 0){
                    // DLECount is an even number so this is not the end of a packet
                    return null;
                }


                // Ensure packet begins with a valid startDelimiter
                if (buffer[0] != dle && buffer[1] != stx)
                {
                    Console.WriteLine("Popped a packet without a start delimiter");
                    return null;
                }

                return DeStuffPacket(buffer);
            }

            return null;
        }

        public static bool RemoteCertificateValidationCallback(
            object sender,
            X509Certificate certificate,
            X509Chain chain,
            SslPolicyErrors sslPolicyErrors)
        {
            if (sslPolicyErrors == SslPolicyErrors.None)
            {
                return true;
            }

            Console.WriteLine("Certificate error: {0}", sslPolicyErrors);
            //Certificate error, may not have the CA installed on client, return true anyway
            return true;
        }
    }

}
