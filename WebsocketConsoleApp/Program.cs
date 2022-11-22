using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices.ComTypes;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
//https://www.codeproject.com/Articles/1063910/WebSocket-Server-in-Csharp
//https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API/Writing_WebSocket_server
class Server
{
    public static void Main()
    {
        string ip = "127.0.0.1";
        int port = 8013;
        var server = new TcpListener(IPAddress.Parse(ip), port);

        server.Start();
        Console.WriteLine("Server has started on {0}:{1}, Waiting for a connection…", ip, port);

        while (true) // Add your exit flag here
        {
            TcpClient client = server.AcceptTcpClient();
            ThreadPool.QueueUserWorkItem(ThreadProc, client);
        } 


        //TcpClient client = server.AcceptTcpClient();
        //Console.WriteLine("A client connected."); 

    }
    private static void sendData(NetworkStream stream, String data)
    {
        byte[] msg = System.Text.Encoding.ASCII.GetBytes(data);

        // Send back a response.
        Write(msg, stream);
    }
    private static void Write(byte[] payload, NetworkStream stream)
    {
        // best to write everything to a memory stream before we push it onto the wire
        // not really necessary but I like it this way
        using (MemoryStream memoryStream = new MemoryStream())
        {
            byte finBitSetAsByte =  (byte)0x80;
            byte byte1 = (byte)(finBitSetAsByte | (byte)1);
            memoryStream.WriteByte(byte1);

            // NB, set the mask flag if we are constructing a client frame
            byte maskBitSetAsByte = (byte)0x00;

            // depending on the size of the length we want to write it as a byte, ushort or ulong
            if (payload.Length < 126)
            {
                byte byte2 = (byte)(maskBitSetAsByte | (byte)payload.Length);
                memoryStream.WriteByte(byte2);
            }
            else if (payload.Length <= ushort.MaxValue)
            {
                byte byte2 = (byte)(maskBitSetAsByte | 126);
                memoryStream.WriteByte(byte2);
                //BinaryReaderWriter.WriteUShort((ushort)payload.Length, memoryStream, false);
            }
            else
            {
                byte byte2 = (byte)(maskBitSetAsByte | 127);
                memoryStream.WriteByte(byte2);
                //BinaryReaderWriter.WriteULong((ulong)payload.Length, memoryStream, false);
            }

            // if we are creating a client frame then we MUST mack the payload as per the spec
            //if (_isClient)
            //{
            //    byte[] maskKey = new byte[WebSocketFrameCommon.MaskKeyLength];
            //    _random.NextBytes(maskKey);
            //    memoryStream.Write(maskKey, 0, maskKey.Length);

            //    // mask the payload
            //    WebSocketFrameCommon.ToggleMask(maskKey, payload);
            //}

            memoryStream.Write(payload, 0, payload.Length);
            byte[] buffer = memoryStream.ToArray();
            stream.Write(buffer, 0, buffer.Length);
        }
    }
    private static void SendMessageOnInterval(object obj)
    {
        var stream = (NetworkStream)obj;
        while (true)
        {
            Thread.Sleep(1000);
            sendData(stream, DateTime.Now.ToString());
        }
    }

    private static void ThreadProc(object obj)
    {
        var client = (TcpClient)obj;
        NetworkStream stream = client.GetStream();
        // enter to an infinite cycle to be able to handle every change in stream
        while (true)
        {
            if (!client.Connected) return;
            while (!stream.DataAvailable) ;
            while (client.Available < 3) ; // match against "get"

            byte[] bytes = new byte[client.Available];
            stream.Read(bytes, 0, client.Available);
            string s = Encoding.UTF8.GetString(bytes);

            if (Regex.IsMatch(s, "^GET", RegexOptions.IgnoreCase))
            {
                Console.WriteLine("=====Handshaking from client=====\n{0}", s);

                // 1. Obtain the value of the "Sec-WebSocket-Key" request header without any leading or trailing whitespace
                // 2. Concatenate it with "258EAFA5-E914-47DA-95CA-C5AB0DC85B11" (a special GUID specified by RFC 6455)
                // 3. Compute SHA-1 and Base64 hash of the new value
                // 4. Write the hash back as the value of "Sec-WebSocket-Accept" response header in an HTTP response
                string swk = Regex.Match(s, "Sec-WebSocket-Key: (.*)").Groups[1].Value.Trim();
                string swka = swk + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
                byte[] swkaSha1 = System.Security.Cryptography.SHA1.Create().ComputeHash(Encoding.UTF8.GetBytes(swka));
                string swkaSha1Base64 = Convert.ToBase64String(swkaSha1);

                // HTTP/1.1 defines the sequence CR LF as the end-of-line marker
                byte[] response = Encoding.UTF8.GetBytes(
                    "HTTP/1.1 101 Switching Protocols\r\n" +
                    "Connection: Upgrade\r\n" +
                    "Upgrade: websocket\r\n" +
                    "Sec-WebSocket-Accept: " + swkaSha1Base64 + "\r\n\r\n");

                stream.Write(response, 0, response.Length);
                ThreadPool.QueueUserWorkItem(SendMessageOnInterval, stream);
            }
            else
            {
                bool fin = (bytes[0] & 0b10000000) != 0,
                    mask = (bytes[1] & 0b10000000) != 0; // must be true, "All messages from the client to the server have this bit set"
                int opcode = bytes[0] & 0b00001111; // expecting 1 - text message


                ulong offset = 2;
                ulong msglen = (ulong)(bytes[1] & 0b01111111);

                if (msglen == 126)
                {
                    // bytes are reversed because websocket will print them in Big-Endian, whereas
                    // BitConverter will want them arranged in little-endian on windows
                    msglen = BitConverter.ToUInt16(new byte[] { bytes[3], bytes[2] }, 0);
                    offset = 4;
                }
                else if (msglen == 127)
                {
                    // To test the below code, we need to manually buffer larger messages — since the NIC's autobuffering
                    // may be too latency-friendly for this code to run (that is, we may have only some of the bytes in this
                    // websocket frame available through client.Available).
                    msglen = BitConverter.ToUInt64(new byte[] { bytes[9], bytes[8], bytes[7], bytes[6], bytes[5], bytes[4], bytes[3], bytes[2] }, 0);
                    offset = 10;
                }

                if (msglen == 0)
                {
                    Console.WriteLine("msglen == 0");
                }
                else if (mask)
                {
                    byte[] decoded = new byte[msglen];
                    byte[] masks = new byte[4] { bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3] };
                    offset += 4;

                    for (ulong i = 0; i < msglen; ++i)
                        decoded[i] = (byte)(bytes[offset + i] ^ masks[i % 4]);

                    string text = Encoding.UTF8.GetString(decoded);
                    sendData(stream, "Roger that.");
                    Console.WriteLine("{0}", text);
                }
                else
                    Console.WriteLine("mask bit not set");

                Console.WriteLine();
            }

        }
    }
}