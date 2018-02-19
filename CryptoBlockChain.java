import java.util.*; import java.io.*; import java.net.*; import java.util.concurrent.atomic.*;
import java.security.*;import java.nio.charset.StandardCharsets;
public class CryptoBlockChain { // run: 'java BlockChain' or  'java BlockChain <nodes> <difficulty> <blocks>' 
  static class Block { String id = ""; int state; Block prev, alt; Set<String> records; long stamp; }
  static int node_count, node_maxcount, blk_difficulty, mine_ct, max_blocks; 
  final static AtomicBoolean run = new AtomicBoolean(true); 
  final static AtomicInteger block_count = new AtomicInteger(1);
  public static void main(String[] args) throws IOException { // run network
    node_maxcount  = (args.length > 0) ? Integer.parseInt(args[0]) : 10;
    blk_difficulty = (args.length > 1) ? Integer.parseInt(args[1]) : 5;
    mine_ct        = (args.length > 2) ? 10000000*Integer.parseInt(args[2]) : 50000000;
    max_blocks     = (args.length > 3) ? Integer.parseInt(args[3]) : 50;
    Block zero = new Block(); zero.stamp = System.currentTimeMillis();
    for (int i = 0; i < node_maxcount; i++)  startNode(zero);
  }
  static void startNode(Block zero) throws IOException {
    Block b = new Block(); b.prev = zero; b.state = 2; b.records = new TreeSet<>((x, y)->x.compareTo(y));
    startListener(++node_count, b);
    startMiner(node_count, b);
  }
  static void startMiner(final int id, final Block scratch) throws IOException {
    (new Thread() { @Override public void run() {
      try {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        DatagramSocket udpSocket = new DatagramSocket();
        InetAddress mcIPAddress = InetAddress.getByName("230.1.1.1");
        int nonce_idx = 0, nonce = 0; byte[] header = null; 
        while (run.get()) {
          String msgstr  = null;
          if (block_count.get() > max_blocks) { msgstr = "ALL HALT AND DUMP"; run.set(false); } // halt
          else if (scratch.state != 0) { // reset // new txn/block future: new Merkle
            String header_str = scratch.prev.id + toHex(md.digest(Arrays.toString(scratch.records.toArray(new String[0])).getBytes(StandardCharsets.UTF_8))) +  "00000000";
            header = hexStringToBytes(header_str);
            nonce_idx = header.length-4;
            nonce = scratch.state = 0;
          } 
          for (int lim = randN(mine_ct), i = 0; i <  lim && msgstr == null; i++, nonce++) { // mine
            header[nonce_idx]   = (byte)(nonce >>> 24);
            header[nonce_idx+1] = (byte)(nonce >>> 16);
            header[nonce_idx+2] = (byte)(nonce >>>  8);
            header[nonce_idx+2] = (byte)(nonce);
            byte[] hash = md.digest(header);
            if (fit_p(hash, blk_difficulty) && scratch.state == 0) { // mined new block!!
              scratch.id = toHex(hash);
              // do not scratch.records.add(String.format("MINT 50btc to %x", randN(1000000))); // miner's reward
              scratch.stamp = System.currentTimeMillis();
              String txns = Arrays.toString(scratch.records.toArray(new String[0]));
              msgstr = String.format("BLN %s %s %d | MINT 50btc to %x, %s", scratch.id, scratch.prev.id, scratch.stamp, randN(1000000), txns.substring(1,txns.length()-1));
              scratch.state = 2; 
              block_count.getAndIncrement(); 
            } 
          }
          if (msgstr == null && randN(1000) < 100) { // in 10% cases, send txn
            msgstr = String.format("TXN at %tT %x pays %.3fbtc to %x", new Date(), randN(1000000), 10*Math.random(), randN(1000000));
            scratch.state = 1; scratch.records.add(msgstr); // delete? - redundand with listener input.
          }
          if (msgstr != null) {
            byte[] msg = msgstr.getBytes();
            udpSocket.send(new DatagramPacket(msg, msg.length, mcIPAddress, 9090));
            if (node_maxcount < 10 || !msgstr.startsWith("TXN")) System.out.println("node" + id + "> " + msgstr);
            if (msgstr.startsWith("ALL HALT"))
              for (int i = 0; i < 10; i++) {
                Thread.sleep(100);    
                udpSocket.send(new DatagramPacket(msg, msg.length, mcIPAddress, 9090));
              }
          }
        }
        udpSocket.close();
      } catch (Exception ex) { ex.printStackTrace(); }
      System.out.println("node" + id + " sender exiting.");
    }}).start();
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
          if (msg.startsWith("TXN")) {
            if (scratch.records.contains(msg)) ; // do nothing
            else { // add record // System.out.println("node" + id + ": added it.");
              scratch.records.add(msg); scratch.state = 1; // state 1 is 'dirty', stop mining
            }
          } else if (msg.startsWith("BLN")) { // validate, then acquire new block and chain it
            String[] header_arr = msg.substring(0, msg.indexOf("|")).split(" ");
            String block_prev = header_arr[2];
            if (scratch.alt != null) { // time to resolve conflict
              if (block_prev.equals(scratch.alt.id)) scratch.prev = scratch.alt; 
              scratch.alt = null; 
            }
            List<String> txns = Arrays.asList(msg.substring(msg.indexOf("|")+2).split(", ")); // pretend list is validated (signatures etc)
            boolean current_txn = true; // we want to make sure none of the txns are stored in prev blocks!
            for (Block b = scratch.prev; b.prev != null && (current_txn = Collections.disjoint(b.records, txns)); b = b.prev);
            if (!current_txn) System.out.println("-- block contains spent txns, rejecting it: " + msg);
            else { // proceed
              Block b = new Block(); 
              if (!block_prev.equals(scratch.prev.id)) { // very rare
                if (block_prev.equals(scratch.prev.prev.id)) { // contestant
                  { b.prev = scratch.prev.prev; scratch.alt = b; } 
                } else System.out.println("-- node"+id+": Unresloved Collision with prev.id=" + scratch.prev.id + " " +  msg);
              } else { b.prev = scratch.prev; scratch.prev = b; }
              b.id = header_arr[1]; b.stamp = Long.parseLong(header_arr[3]); 
              (b.records = new TreeSet<>((x, y)->x.compareTo(y))).addAll(txns);
              scratch.state = 2; scratch.records.removeAll(txns); // scratch.id = null;
              if (scratch.records.size() != 0) System.out.println("-- node"+id+": left out of last seen block: " + Arrays.toString(scratch.records.toArray(new String[0])));
            }
          } else ; // complain? System.out.println("node "+id+ ": got unknown command!");
        }
        String blockchain = "";
        for (Block b = scratch.prev; b.prev != null; b = b.prev) 
          blockchain = String.format("-------\n%s %s %d %s\n", b.id, b.prev.id, b.stamp, Arrays.toString(b.records.toArray(new String[0]))) + blockchain;
        try (PrintWriter out = new PrintWriter("blockchain"+id+".txt")) { out.println(blockchain); }
        mcSocket.leaveGroup(mcIPAddress);
        mcSocket.close();
      } catch (Exception ex) { ex.printStackTrace(); }
      System.out.println("node" + id + " listener exiting.");
    }}).start();
  }
  static int randN(int range) { return (int)Math.round(Math.random()*range); }
  static boolean fit_p(byte[] hash, int difficulty) { // does hash have given difficulty?
    int zerobytes = difficulty/2, half = difficulty%2;
    boolean success = true;
    for (int i = 0; i < zerobytes && success; i++) if (hash[i] != 0) success = false;
    if (success && half != 0 && (hash[zerobytes] & 0xf0) != 0) success = false;
    return success;
  }
  static String toHex(byte[] data) {
    StringBuilder sb = new StringBuilder();
    for (byte b: data) sb.append(String.format("%02x", b&0xff));
    return sb.toString();
  }
  static byte[] hexStringToBytes(String s) { // from stackoverflow
    int len = s.length();
    byte[] data = new byte[len / 2];
    for (int i = 0; i < len; i += 2)
      data[i / 2] = (byte)((Character.digit(s.charAt(i), 16) << 4)
                           + Character.digit(s.charAt(i+1), 16));
    return data;
  }
}
