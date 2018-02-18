import java.util.*; import java.io.*; import java.net.*;
public class BlockChain {
  static class Block { int id, state, count;  Block prev; Set<String> records; long stamp; }
  static int node_count, difficulty, max_blocks; static boolean run = true;
  public static void main(String[] args) throws IOException {
    int nodemx = (args.length > 0) ? Integer.parseInt(args[0]) : 10;
    difficulty = (args.length > 1) ? Integer.parseInt(args[1]) : 4;
    max_blocks = (args.length > 2) ? Integer.parseInt(args[2]) : 50;
    Block zero = new Block(); zero.stamp = System.currentTimeMillis();
    for (int i = 0; i < nodemx; i++)  startNode(zero);
  }
  static void startNode(Block zero) throws IOException {
    Block b = new Block(); b.prev = zero; b.id = 1; b.records = new TreeSet<>((x, y)->x.compareTo(y));
    startListener(++node_count, b);
    startSender(node_count, b);
  }
  static void startListener(final int id, final Block scratch) throws IOException {
    (new Thread() { @Override public void run() {
      try {
        InetAddress mcIPAddress = InetAddress.getByName("230.1.1.1");
        MulticastSocket mcSocket = new MulticastSocket(9090);
        mcSocket.joinGroup(mcIPAddress);
        DatagramPacket packet = new DatagramPacket(new byte[1024], 1024);           
        while (run) {
          mcSocket.receive(packet);
          String msg = new String(packet.getData(), packet.getOffset(), packet.getLength());
          System.out.println("node" + id + "< " + msg);
          if (msg.startsWith("TXN")) {
            if (scratch.records.contains(msg)) ; // do nothing
            else { // add record // System.out.println("node" + id + ": added it.");
              scratch.records.add(msg); scratch.state = 1; // state 1 is 'dirty', stop mining
            }
          } else if (msg.startsWith("BLN")) { // acquire new block and chain it
            Block b = new Block(); b.prev = scratch.prev; scratch.prev = b; 
            String[] header_arr = msg.substring(0, msg.indexOf("|")).split(" ");
            List<String> txns = Arrays.asList(msg.substring(msg.indexOf("|")+2).split(", "));
            if (Integer.parseInt(header_arr[2]) != b.prev.id) System.out.println("-- Collision with prev.id=" + b.prev.id + " " +  msg);
            b.id = Integer.parseInt(header_arr[1]); b.stamp = Long.parseLong(header_arr[3]); 
            (b.records = new TreeSet<>((x, y)->x.compareTo(y))).addAll(txns);
            scratch.state = 1; scratch.id = b.id+1; scratch.records.removeAll(txns); 
            if (scratch.records.size() != 0) System.out.println("-- node "+id+" records left out of last seen block: " + Arrays.toString(scratch.records.toArray(new String[0])));
          } else ; // complain? System.out.println("node "+id+ ": got unknown command!");
        }
        String blockchain = "";
        for (Block b = scratch.prev; b.prev != null; b = b.prev) 
          blockchain = String.format("-------\n%d %d %d %s\n", b.id, b.prev.id, b.stamp, Arrays.toString(b.records.toArray(new String[0]))) + blockchain;
        try (PrintWriter out = new PrintWriter("blockchain"+id+".txt")) { out.println(blockchain); }
        mcSocket.leaveGroup(mcIPAddress);
        mcSocket.close();
      } catch (Exception ex) { ex.printStackTrace(); }
    }}).start();
  }
  static void startSender(final int id, final Block scratch) throws IOException {
    (new Thread() { @Override public void run() {
      try {
        DatagramSocket udpSocket = new DatagramSocket();
        InetAddress mcIPAddress = InetAddress.getByName("230.1.1.1");
        while (run) {
          Thread.sleep(randN(5000));
          String msgstr  = null;
          if (scratch.count > difficulty) { // halt at max_blocks, or create new block and broadcast it
            scratch.id = scratch.prev.id + 1;
            if (scratch.id > max_blocks) { msgstr = "ALL HALT AND DUMP"; run = false; } // halt
            else { // mint block
              scratch.stamp = System.currentTimeMillis();
              String txns = Arrays.toString(scratch.records.toArray(new String[0]));
              msgstr = String.format("BLN %d %d %d | %s", scratch.id, scratch.prev.id, scratch.stamp, txns.substring(1,txns.length()-1));
              scratch.state = 1; scratch.count++; scratch.count = 0;
            }
          } else { // send msg
            msgstr = String.format("TXN at %tT %x pays %.3fbtc to %x", new Date(), randN(1000000), 10*Math.random(), randN(1000000));
            scratch.state = 1; scratch.count++; scratch.records.add(msgstr);
          }
          byte[] msg = msgstr.getBytes();
          DatagramPacket packet = new DatagramPacket(msg, msg.length, mcIPAddress, 9090);
          udpSocket.send(packet);
          System.out.println("node" + id + "> " + msgstr);
        }
        udpSocket.close();
      } catch (Exception ex) { ex.printStackTrace(); }
    }}).start();
  }
  static int randN(int range) { return (int)Math.round(Math.random()*range); }
}
