import java.util.*; import java.io.*; import java.net.*; import java.util.concurrent.atomic.*;
public class BlockChain {
  static class Block { int id, state, count; Block prev, alt; Set<String> records; long stamp; }
  static int node_count, node_maxcount, difficulty, max_blocks; 
  final static AtomicBoolean run = new AtomicBoolean(true); 
  final static AtomicInteger block_count = new AtomicInteger(1);
  public static void main(String[] args) throws IOException {
    node_maxcount  = (args.length > 0) ? Integer.parseInt(args[0]) : 10;
    difficulty     = (args.length > 1) ? Integer.parseInt(args[1]) : 4;
    max_blocks     = (args.length > 2) ? Integer.parseInt(args[2]) : 50;
    Block zero = new Block(); zero.stamp = System.currentTimeMillis();
    for (int i = 0; i < node_maxcount; i++)  startNode(zero);
  }
  static void startNode(Block zero) throws IOException {
    Block b = new Block(); b.prev = zero; b.records = new TreeSet<>((x, y)->x.compareTo(y));
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
        while (run.get()) {
          mcSocket.receive(packet);
          String msg = new String(packet.getData(), packet.getOffset(), packet.getLength());
          if (node_maxcount < 5 || !msg.startsWith("TXN")) System.out.println("node" + id + "< " + msg);
          if (msg.startsWith("TXN")) {
            if (scratch.records.contains(msg)) ; // do nothing
            else { // add record // System.out.println("node" + id + ": added it.");
              scratch.records.add(msg); scratch.state = 1; // state 1 is 'dirty', stop mining
            }
          } else if (msg.startsWith("BLN")) { // validate, then acquire new block and chain it
            String[] header_arr = msg.substring(0, msg.indexOf("|")).split(" ");
            int block_prev = Integer.parseInt(header_arr[2]); 
            if (scratch.alt != null) { // time to resolve conflict
              if (block_prev == scratch.alt.id) scratch.prev = scratch.alt; 
              scratch.alt = null; 
            }
            if (block_prev != scratch.prev.id) { // very rare
              if (block_prev == scratch.prev.prev.id) { // contestant
                scratch.state = -1;
              } else System.out.println("-- Unresloved Collision with prev.id=" + scratch.prev.id + " " +  msg);
            }
            List<String> txns = Arrays.asList(msg.substring(msg.indexOf("|")+2).split(", ")); // pretend list is validated (signatures etc)
            boolean current_txn = true; // we want to make sure none of the txns are stored in prev blocks!
            for (Block b = scratch.prev; b.prev != null && (current_txn = Collections.disjoint(b.records, txns)); b = b.prev);
            if (!current_txn) System.out.println("-- block contains spent txns, rejecting it: " + msg);
            else { // proceed
              Block b = new Block(); 
              if (scratch.state == -1) { b.prev = scratch.prev.prev; scratch.alt = b; } 
              else { b.prev = scratch.prev; scratch.prev = b; }
              b.id = Integer.parseInt(header_arr[1]); b.stamp = Long.parseLong(header_arr[3]); 
              (b.records = new TreeSet<>((x, y)->x.compareTo(y))).addAll(txns);
              scratch.state = 1; scratch.id = b.id+1; scratch.records.removeAll(txns); 
              if (scratch.records.size() != 0) System.out.println("-- node"+id+": left out of last seen block: " + Arrays.toString(scratch.records.toArray(new String[0])));
            }
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
        while (run.get()) {
          Thread.sleep(randN(node_maxcount*2000));
          String msgstr  = null;
          if (scratch.count > difficulty) { // halt at max_blocks, or create new block and broadcast it
            if (block_count.get() > max_blocks) { msgstr = "ALL HALT AND DUMP"; run.set(false); } // halt
            else { // mint block
              scratch.id = block_count.getAndIncrement();
              scratch.stamp = System.currentTimeMillis();
              String txns = Arrays.toString(scratch.records.toArray(new String[0]));
              msgstr = String.format("BLN %d %d %d | MINT 50btc to %x, %s", scratch.id, scratch.prev.id, scratch.stamp, randN(1000000), txns.substring(1,txns.length()-1));
              scratch.state = 1; scratch.count++; scratch.count = 0;
            }
          } else { // send msg
            msgstr = String.format("TXN at %tT %x pays %.3fbtc to %x", new Date(), randN(1000000), 10*Math.random(), randN(1000000));
            scratch.state = 1; scratch.count++; scratch.records.add(msgstr);
          }
          byte[] msg = msgstr.getBytes();
          DatagramPacket packet = new DatagramPacket(msg, msg.length, mcIPAddress, 9090);
          udpSocket.send(packet);
          if (node_maxcount < 5 || !msgstr.startsWith("TXN")) System.out.println("node" + id + "> " + msgstr);
        }
        udpSocket.close();
      } catch (Exception ex) { ex.printStackTrace(); }
    }}).start();
  }
  static int randN(int range) { return (int)Math.round(Math.random()*range); }
}
