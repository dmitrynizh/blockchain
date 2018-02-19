import java.util.*; import java.io.*; import java.net.*; import java.util.concurrent.atomic.*;
public class BlockChain { // run: 'java BlockChain' or  'java BlockChain <nodes> <difficulty> <blocks>' 
  static class Block { int id, POW; Block prev, alt; Set<String> records; long stamp; }
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
        DatagramPacket packet = new DatagramPacket(new byte[4*1024], 4*1024); 
        while (run.get()) {
          mcSocket.receive(packet);
          String msg = new String(packet.getData(), packet.getOffset(), packet.getLength());
          if (node_maxcount < 5) System.out.println("node" + id + "< " + msg);
          if (msg.startsWith("T")) { // got a txn; check for 'spent' status? 
            if (scratch.records.contains(msg)) ; // do nothing? for now...
            else scratch.records.add(msg); // real miner must stop mining
          } else if (msg.startsWith("B")) { // got block. validate, then acquire  and chain it
            String[] header_arr = msg.substring(0, msg.indexOf("|")).split(" ");
            int block_prev_id = Integer.parseInt(header_arr[2]); 
            if (scratch.alt != null) { // time to resolve conflict
              if (block_prev_id == scratch.alt.id) scratch.prev = scratch.alt; // alt won
              scratch.alt = null; 
            }
            List<String> txns = Arrays.asList(msg.substring(msg.indexOf("|")+2).split(", ")); // pretend list is validated (signatures etc)
            boolean current_txn = true; // we want to make sure none of the txns are stored in prev blocks!
            for (Block b = scratch.prev; b.prev != null && (current_txn = Collections.disjoint(b.records, txns)); b = b.prev);
            if (!current_txn) { System.out.println("-- node"+id+": block contains spent txns, rejecting it: " + msg); }
            else { // proceed acceting new block
              Block b = new Block(); 
              if (block_prev_id != scratch.prev.id) { // very rare but can happen
                if (block_prev_id == scratch.prev.prev.id) { b.prev = scratch.prev.prev; scratch.alt = b; } // contestant
                else System.out.println("-- node"+id+": Unresloved Collision with prev.id=" + scratch.prev.id + " " +  msg);
              } else { b.prev = scratch.prev; scratch.prev = b; }
              b.id = Integer.parseInt(header_arr[1]); b.stamp = Long.parseLong(header_arr[3]); 
              (b.records = new TreeSet<>((x, y)->x.compareTo(y))).addAll(txns);
              scratch.id = b.id+1; scratch.records.removeAll(txns); 
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
      System.out.println("node" + id + " listener exiting.");
    }}).start();
  }
  static void startSender(final int id, final Block scratch) throws IOException {
    (new Thread() { @Override public void run() {
      try {
        DatagramSocket udpSocket = new DatagramSocket();
        InetAddress mcIPAddress = InetAddress.getByName("230.1.1.1");
        while (run.get()) {
          for (int d = randN(2000), i = node_maxcount; i > 0 && run.get(); i--) Thread.sleep(d);
          if (!run.get()) break;
          String msgstr  = null;
          if (scratch.POW > difficulty) { // halt at max_blocks, or create new block and broadcast it
            if (block_count.get() > max_blocks) { msgstr = "ALL HALT AND DUMP"; run.set(false); } // halt
            else { // mint block
              scratch.id = block_count.getAndIncrement(); scratch.POW = 0;
              // do not, put in block scratch.records.add(String.format("MINT 50btc to %x", randN(1000000))); // miner's reward
              String txns = Arrays.toString(scratch.records.toArray(new String[0]));
              msgstr = String.format("B %d %d %d | MINT 50btc to %x, %s", scratch.id, scratch.prev.id, System.currentTimeMillis(),  randN(1000000), txns.substring(1,txns.length()-1));
            }
          } else { // send txn msg
            msgstr = String.format("T at %tT %x pays %.3fbtc to %x", new Date(), randN(1000000), 10*Math.random(), randN(1000000));
            scratch.POW++; // do not do it scratch.records.add(msgstr);
          }
          byte[] msg = msgstr.getBytes();
          if (node_maxcount < 5 || !msgstr.startsWith("T")) System.out.println("node" + id + "> " + msgstr);
          for (int i = 0; i < 10; i++) { 
            udpSocket.send(new DatagramPacket(msg, msg.length, mcIPAddress, 9090));
            if (!msgstr.startsWith("ALL HALT")) break;
            Thread.sleep(100); 
          }
        }
        udpSocket.close();
      } catch (Exception ex) { ex.printStackTrace(); }
      System.out.println("node" + id + " sender exiting.");
    }}).start();
  }
  static int randN(int range) { return (int)Math.round(Math.random()*range); }
}
