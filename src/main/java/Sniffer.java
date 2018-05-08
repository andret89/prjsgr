import com.sun.jna.Platform;
import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.*;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.util.NifSelector;

import java.io.IOException;
import java.time.Instant;

import static java.lang.System.currentTimeMillis;

public class Sniffer {

    static PcapNetworkInterface getNetworkDevice() {
        PcapNetworkInterface device = null;
        try {
            device = new NifSelector().selectNetworkInterface();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return device;
    }

    public static void main(String[] args) throws PcapNativeException, NotOpenException {
        PcapNetworkInterface device = getNetworkDevice();
        System.out.println("You chose: " + device);

        // New code below here
        if (device == null) {
            System.out.println("No device chosen.");
            System.exit(1);
        }

        int snapLen = 65536;
        int timeout = 10;
        final PcapHandle handle;
        handle = device.openLive(snapLen, PromiscuousMode.PROMISCUOUS, timeout);

        final PcapDumper dumper = handle.dumpOpen("out.pcap");

        // Set a filter to only listen for tcp packets on port 80 (HTTP)
        String filter = "tcp port 80";
        handle.setFilter(filter, BpfCompileMode.OPTIMIZE);

        // Create a listener that defines what to do with the received packets
        PacketListener listener = packet -> {
            // Print packet information to screen
            System.out.println(handle.getTimestampPrecision());
            System.out.println(packet);

            // Dump packets to file
            try {
                dumper.dump(packet);
            } catch (NotOpenException e) {
                e.printStackTrace();
            }
        };

        // Tell the handle to loop using the listener we created
        try {
            int maxPackets = 50;
            handle.loop(maxPackets, listener);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        // Print out handle statistics
        PcapStat stats = handle.getStats();
        System.out.println("Packets received: " + stats.getNumPacketsReceived());
        System.out.println("Packets dropped: " + stats.getNumPacketsDropped());
        System.out.println("Packets dropped by interface: " + stats.getNumPacketsDroppedByIf());
        // Supported by WinPcap only
        if (Platform.isWindows()) {
            System.out.println("Packets captured: " + stats.getNumPacketsCaptured());
        }

        // Cleanup when complete
        dumper.close();
        handle.close();
    }
}
