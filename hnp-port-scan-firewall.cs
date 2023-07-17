using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Diagnostics;

class Hnp_PortScanner
{
    static void Main()
    {
        List<int> hnp_targetPorts = new List<int> { 12345, 80, 443 }; // List of target ports or port range to monitor
        int hnp_emptyPacketThreshold = 5; // Number of empty packets before the IP address is blocked
        int hnp_synPacketThreshold = 10; // Number of SYN packets before the IP address is blocked

        Dictionary<IPAddress, int> hnp_emptyPackets = new Dictionary<IPAddress, int>();
        Dictionary<IPAddress, int> hnp_synPackets = new Dictionary<IPAddress, int>();

        using (UdpClient hnp_udpClient = new UdpClient())
        using (TcpListener hnp_tcpListener = new TcpListener(IPAddress.Any, hnp_targetPorts[0]))
        {
            hnp_tcpListener.Start();

            Console.WriteLine("Port Scanner is listening...");

            while (true)
            {
                try
                {
                    // Monitoring UDP packets
                    IPEndPoint hnp_udpSenderEndPoint = new IPEndPoint(IPAddress.Any, 0);
                    byte[] hnp_udpReceivedBytes = hnp_udpClient.Receive(ref hnp_udpSenderEndPoint);

                    if (hnp_targetPorts.Contains(hnp_udpSenderEndPoint.Port) && hnp_udpReceivedBytes.Length == 0)
                    {
                        if (!hnp_emptyPackets.ContainsKey(hnp_udpSenderEndPoint.Address))
                            hnp_emptyPackets[hnp_udpSenderEndPoint.Address] = 0;

                        hnp_emptyPackets[hnp_udpSenderEndPoint.Address]++;

                        Console.WriteLine($"Empty UDP packet received from {hnp_udpSenderEndPoint.Address}:{hnp_udpSenderEndPoint.Port}. Possible port scan attempt.");

                        if (hnp_emptyPackets[hnp_udpSenderEndPoint.Address] >= hnp_emptyPacketThreshold)
                        {
                            Hnp_BlockIpAddress(hnp_udpSenderEndPoint.Address);
                            Console.WriteLine($"IP address {hnp_udpSenderEndPoint.Address} has been blocked.");
                            hnp_emptyPackets.Remove(hnp_udpSenderEndPoint.Address);
                        }
                    }

                    // Monitoring TCP-SYN packets
                    TcpClient hnp_tcpClient = hnp_tcpListener.AcceptTcpClient();
                    IPEndPoint hnp_tcpSenderEndPoint = (IPEndPoint)hnp_tcpClient.Client.RemoteEndPoint;

                    if (hnp_targetPorts.Contains(hnp_tcpSenderEndPoint.Port))
                    {
                        if (!hnp_synPackets.ContainsKey(hnp_tcpSenderEndPoint.Address))
                            hnp_synPackets[hnp_tcpSenderEndPoint.Address] = 0;

                        hnp_synPackets[hnp_tcpSenderEndPoint.Address]++;

                        Console.WriteLine($"TCP-SYN packet received from {hnp_tcpSenderEndPoint.Address}:{hnp_tcpSenderEndPoint.Port}. Possible port scan attempt.");

                        if (hnp_synPackets[hnp_tcpSenderEndPoint.Address] >= hnp_synPacketThreshold)
                        {
                            Hnp_BlockIpAddress(hnp_tcpSenderEndPoint.Address);
                            Console.WriteLine($"IP address {hnp_tcpSenderEndPoint.Address} has been blocked.");
                            hnp_synPackets.Remove(hnp_tcpSenderEndPoint.Address);
                        }
                    }

                    hnp_tcpClient.Close();
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error occurred: {ex.Message}");
                }
            }
        }
    }

    static void Hnp_BlockIpAddress(IPAddress hnp_ipAddress)
    {
        string hnp_arguments = $"advfirewall firewall add rule name=\"Block IP\" dir=in interface=any action=block remoteip={hnp_ipAddress}";
        Process.Start("netsh", hnp_arguments)?.WaitForExit();
    }
}
