import java.util.*; import java.io.*; import java.net.*; import java.math.*;
import java.security.*; import java.security.spec.*; import static java.nio.charset.StandardCharsets.UTF_8; 
public class CryptoBlockChain { // (c) 2018 dmitrynizh. MIT License.
  static class Block { String hash; int ht, state, nonce; Block prev, alt; Set<String> txns; HashMap<String,String>d; long stamp;}
  static int nodes, difficulty, effort, blockMx, reward=50000; static class Cred { String pk; PrivateKey sk; Cred(String p, PrivateKey s) {pk=p;sk=s;}} 
  static volatile int block_count; static volatile boolean run = true; static Stack<String> ads = new Stack<>(); static final String E = "";
  public static void main(String[] args) throws Exception { // run network
    nodes      = (args.length > 0) ? toI(args[0]) : 7;
    difficulty = (args.length > 1) ? toI(args[1]) : 49; if (difficulty <= 10) difficulty *= 8;
    effort     = (args.length > 2) ? toI(args[2]) : 1; effort *= 10000000;
    blockMx = (args.length > 3) ? toI(args[3]) : 20;
    Block zero = new Block(); zero.stamp = System.currentTimeMillis(); zero.hash = "00";
    for (int i = 0; i < nodes; i++) startNode(i, zero, new Block(), InetAddress.getByName("230.1.1.1"), new Stack<>(), new Vector<>());
  }
  static void startNode(int id, Block zero, Block b, InetAddress ip, Stack<String> mq, Vector<Cred> w) throws Exception {
    b.prev = zero; b.state = 2; b.txns = new TreeSet<>((x, y)->x.compareTo(y)); b.d = new HashMap<>();  
    startListener(ip, id, b, KeyFactory.getInstance("EC"), mq, MessageDigest.getInstance("SHA-256"), w); startMiner(ip, id, b, mq, MessageDigest.getInstance("SHA-256"), w);
  }
  static void startMiner(InetAddress ip, int id, Block scratch, Stack<String> mq, MessageDigest md, Vector<Cred> w) {
    (new Thread() { @Override public void run() {
      try (PrintWriter log = new PrintWriter("miner"+id+".log")) {
        DatagramSocket udpSocket = new DatagramSocket(); int nonce = 0; byte[] header = null; 
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC"); keyGen.initialize(256,SecureRandom.getInstance("SHA1PRNG")); 
        KeyPair pair = keyGen.generateKeyPair(); PrivateKey sk = pair.getPrivate(); 
        String pk58 = to58(pair.getPublic().getEncoded()), txs="", root, coinbase; w.add(new Cred(pk58, sk));
        while (run) { // mine continuously, rehashing when new stuff comes, and sending blocks, or txns
          //System.out.println("-- height: " + scratch.prev.ht);
          if (scratch.prev.ht > blockMx || block_count > blockMx+blockMx/3) { mq.push("ALL HALT AND DUMP"); run = false; } // halt
          else if (scratch.state != 0) { // reset as saw new txn/block.  future: proper Merkle
            Signature sig = Signature.getInstance("SHA256withECDSA"); KeyFactory kf = KeyFactory.getInstance("EC"); int fee[]={0};
            Block b = new Block(); b.d = new HashMap<>(); b.prev = scratch.prev; // b.d detects and rejects any double spends in the new batch 
            log(log, "valid: %s",txs = seq(toA(scratch.txns,"")).filter(t->null!=verifyTx(t,fee,md,b,sig,kf,log)).reduce("",(x,y)->x+", "+y));
            log(log, coinbase = sign(String.format("MINT new coins mBTC= %s %d %s mining reward", pk58, fee[0]+reward, pk58), sk));
            txs = coinbase + txs; root = toHex(md.digest(txs.getBytes(UTF_8)));
            header = asHex(scratch.prev.hash+root+"00000000"); nonce = scratch.state = 0;
          }  // "Each node works on finding a difficult proof-of-work for its block" - see reference [1].
          for (int nonce_idx = header.length-4, lim = randN(effort), i = 0; i <  lim && mq.isEmpty(); i++, nonce++) { // randN sets duration
            for (int x = 0, z = 24; x < 4; x++, z-=8) header[nonce_idx+x] = (byte)(nonce >>> z); // convert int to 4 bytes
            byte[] hash = md.digest(header);
            if (fit_p(hash, difficulty) && scratch.state == 0) { // mined new block!!
              scratch.state = 2; block_count++; // "When a node finds a proof-of-work, it broadcasts the block to all nodes" [1].
              mq.push(String.format("BLN\n%s\n%s\n%d %d\n| %s;", toHex(hash), scratch.prev.hash, nonce, System.currentTimeMillis() ,txs)); // : is end packet
              pair=keyGen.generateKeyPair(); sk = pair.getPrivate(); pk58 = to58(pair.getPublic().getEncoded()); w.add(new Cred(pk58, sk)); // replace keys
            }} 
          if (mq.isEmpty() && randN(100) < 30 && block_count > 3) { // in 30% cases, if funds available, may pay to some pk out of w
            if (ads.size() > nodes/4) {
              String ad = ads.elementAt(randN(ads.size()-1)), a[] = ad.split(" "), ppk = a[0], src=null,sa[]=null,v[], src_pk58=null; 
              int sum = toI(a[1]), fee = randN(sum)/100, has = 0, rem = 0; PrivateKey src_sk=null; //todo if from miner, check that miner mined that X blocks ago
              for (Cred p : w.toArray(new Cred[0])) { // pk must have UO on it that has sum or more and burried deep enough in blockchain
                src_pk58 = p.pk; src_sk = p.sk; src = get(src_pk58,scratch);
                if (get("pending:"+src_pk58,scratch) == null && src != null && get(src,scratch) == null 
                    && ((has = toI((sa=src.split(":"))[0])) >= sum) && scratch.prev.ht - toI(sa[3]) > 3) break; 
              } // the loop above is such constructed that if has >= sum, all set to spend on the ad
              if ((rem = has - sum - fee) >= 0) { // when rem == 0, the 2nd output is 0 btc to _ (nobody)
                String tx, sh = sa[2]; int si = toI(sa[1]); if(randN(100) > 20) ads.remove(ad); //  sims that 20% of posters forget remove ad - sims pk reuse cases
                mq.push(tx=sign(String.format("TXN %tT %d %s %s %d %s %d %s", new Date(), si, sh, src_pk58, sum, ppk, rem, rem==0?"_":pk58), src_sk)); 
                scratch.d.put("pending:"+src_pk58,tx); /*experimental - to avoid double withdrawals*/
                if (rem != 0) {pair=keyGen.generateKeyPair(); sk = pair.getPrivate(); pk58 = to58(pair.getPublic().getEncoded()); w.add(new Cred(pk58, sk)); }//replace keys
              }} else if (ads.size() < nodes && randN(100) < 30) { // advertise some service/goods on 'physical world' ads desk. 
              String adv[] = {"Buying Coins", "Sell Merchandise", "Services", "Charity"}, ad = String.format("%s %d %s", pk58, randN(50000), adv[randN(3)]);
              nodeOut(id, ">" + "posted new craigslist ad: " + ad);
              pair=keyGen.generateKeyPair(); sk = pair.getPrivate(); pk58 = to58(pair.getPublic().getEncoded()); w.add(new Cred(pk58, sk)); ads.push(ad); 
            }}
          if (!mq.isEmpty()) { // from [1]: "New transactions are broadcast to all nodes"
            String msgstr = mq.pop(); if (msgstr.equals("PK+")) msgstr = "PK " + id + " " + pk58;
            byte[] msg = msgstr.getBytes(); if (!msgstr.startsWith("BLN")) Thread.sleep(randN(700)); // still needed
            udpSocket.send(new DatagramPacket(msg, msg.length, ip, 9090));
            // test udpSocket.send(new DatagramPacket("TEST".getBytes(), 4, ip, 9090+2));
            if (nodes <= 10  || msgstr.startsWith("BLN")) nodeOut(id, "> " + msgstr);
            Thread.sleep(randN(500)); // stil keep it
            if (msgstr.startsWith("ALL HALT")) // to force all nodes to quit
              for (int i = 0; i < 20; i++, Thread.sleep(100)) // 10 times plus delay is ugly but works
                udpSocket.send(new DatagramPacket(msg, msg.length, ip, 9090));
            else Thread.sleep(100);
          }
        } udpSocket.close(); nodeOut(id, "> sender exiting."); 
      } catch (Exception ex) { ex.printStackTrace(); } }}).start();
  }
  static void startListener(InetAddress ip, int id, Block scratch, KeyFactory kf, Stack<String> mq, MessageDigest md, Vector<Cred> w) {
    (new Thread() { @Override public void run() { 
      try (PrintWriter log = new PrintWriter("n"+id+".log"); PrintWriter bpw = new PrintWriter("balance"+id+".txt")) {
          MulticastSocket mcs = new MulticastSocket(9090); mcs.joinGroup(ip);
          DatagramPacket packet = new DatagramPacket(new byte[16*1024], 16*1024); 
          Signature sig = Signature.getInstance("SHA256withECDSA");
          while (run) { Thread.sleep(randN(500)); 
            mcs.receive(packet); // method receive blocks the thread until something arrives
            String msg = new String(packet.getData(), packet.getOffset(), packet.getLength());
            if (nodes < 5) nodeOut(id, "< " + msg);
            if (msg.startsWith("TXN") && !scratch.txns.contains(msg)) { // add new record and set state to 1
              scratch.txns.add(msg); // try not to do it.... if (verifyTx(id, msg, md, scratch, sig, kf, log)) { scratch.txns.add(msg); scratch.state = 1; } 
            } else if (msg.startsWith("BLN")) { // validate, then acquire new block and chain it
              if (!msg.endsWith(";")) { log.println("ERROR: block packet corrupted. sz:" + msg.length() + " txt: <" + msg + ">"); continue; }
              msg = msg.substring(0, msg.length()-2); // or -1???
              String hdr = msg.substring(0, msg.indexOf("|")), hdr_a[] = hdr.split("[\\r\\n\\s]+"), hash = hdr_a[1], prv = hdr_a[2]; 
              if (scratch.alt != null) { // time to resolve conflict.  // TODO: think about this and acceptTx....
                if (prv.equals(scratch.alt.hash)) 
                  scratch.prev = scratch.alt; // "Nodes always consider the longest chain to be the correct one"[1]
                scratch.alt = null; 
              } // next, verify txns. "Nodes accept the block only if all transactions in it are valid and not already spent"[1] 
              String h="", txa[] = msg.substring(msg.indexOf("|")+2).split(", "); int i=txa.length-1; // Q: what about those already accepted??
              List<String> txns = Arrays.asList(txa); // we want to make sure none of the new txns are stored in prev blocks!
              Block b = new Block(), sp = scratch.prev, sa = scratch.alt;  // Nodes express their acceptance of the block by working on creating the next block  
              b.d = new HashMap<>(); // in the chain, using the hash of the accepted block as the previous hash - [1]
              if (!prv.equals(scratch.prev.hash)) { // very rare
                if (prv.equals(scratch.prev.prev.hash)) { // contestant
                  b.prev = scratch.prev.prev;  
                  b.ht = b.prev.ht+1; scratch.alt = b; // "save the other branch in case it becomes longer"[1]
                } else log.println("ERROR: seriously orphane block, this is not handled yet. s.p.h:" + scratch.prev.hash + " block: " +  msg);
              } else { b.prev = scratch.prev; scratch.prev = b; b.ht = b.prev.ht+1; } // normal case
              for (int fee[]={0};i >= 0 && (h = verifyTx(txa[i], fee, md, b, sig, kf, log)) != null;i--); // done backwads to compute fees
              if (i == -1) { // all transactions valid and accepted. note: above, consider passing i in to check that i=0 is MINT
                b.hash = hdr_a[1]; b.nonce = toI(hdr_a[3]); b.stamp = Long.parseLong(hdr_a[4]); 
                (b.txns = new TreeSet<>((x, y)->x.compareTo(y))).addAll(txns); scratch.state = 2; // scratch.txns.clear(); // scratch.txns.removeAll(txns); 
              } else { log.println("block's nth n="+i+" txn is invalid, rejecting whole block: " + msg); scratch.prev = sp; scratch.alt = sa; }
              int sum = map(w,c->get(c.pk,scratch)).filter(v->v!=null)
                .mapToInt(s->map(s.split("/"),v->v.split(":")).filter(v->get(v[1]+":"+v[2],scratch)==null).mapToInt(v->toI(v[0])).sum()).sum();
              bpw.printf("At %tc my BTC balance: %4.3f \n", new Date(), ((double)sum)/1000.0); bpw.flush();
            }} // stop run, report
          String blockchain = "", h_txn = ""; Block s = scratch;
          for (Block b = s.prev; b.prev != null; b = b.prev, h_txn = "") { //log.println("B:"+b.hash+" txns: "+txt(b));
            for (String txn : b.txns.toArray(new String[0])) h_txn += to58(md.digest(txn.getBytes(UTF_8))) + ":" + txn;
            blockchain = String.format("Mined: %tc\n hash: %s\n prev: %s\nnonce: %d\n txns:\n%s\n\n", 
                                       new Date(b.stamp), b.hash, b.prev.hash, b.nonce, h_txn) + blockchain;
          } 
          try (PrintWriter pw = new PrintWriter("blockchain"+id+".txt")) { pw.println(blockchain); }
          log(bpw, "\nWallet balances\n", "", map(w,c->gall(c.pk,s)+" on key "+c.pk+".\n: : :").filter(st->!st.startsWith(" on"))
              .map(st->map(st.split("/"),e->e.split(":"))
                   .filter(r->r[0].charAt(0)==' '||get(r[1]+":"+r[2],s)==null).map(a->a[0]).reduce("you have available mBTC: ",(a,b)->a+" "+b))
              .map(v->v.replaceAll(" +", " ")).filter(v->v.indexOf(": on")<0));
          log(bpw, "\nSpending history\n", "",   map(w,c->gall(c.pk,s)+" on key "+c.pk+".\n: : :").filter(st->!st.startsWith(" on"))
              .map(st->map(st.split("/"),e->e.split(":"))
                   .filter(r->r[0].charAt(0)==' '||get(r[1]+":"+r[2],s)!=null).map(a->a[0]).reduce("you spent|redeemed mBTC: ",(a,b)->a+" "+b))
              .map(v->v.replaceAll(" +", " ")).filter(v->v.indexOf(": on")<0));
          nodeOut(id, "> listener exiting."); mcs.leaveGroup(ip); mcs.close();
        } catch (Exception ex) { ex.printStackTrace(); }}}).start();
  }
  static java.util.stream.Stream<Cred> sCred(Collection<Cred> c) { return c.stream(); }
  static <T>   java.util.stream.Stream<T> seq(Collection<T> c) { return c.stream(); }
  static <T>   java.util.stream.Stream<T> seq(T[] a) { return Arrays.stream(a); }
  static <X,Y> java.util.stream.Stream<Y> map(X[] a, java.util.function.Function<? super X,? extends Y> f) { return seq(a).map(f); }
  static <X,Y> java.util.stream.Stream<Y> map(Collection<X>c, java.util.function.Function<? super X,? extends Y> f) { return seq(c).map(f); }
  static <T> void log(PrintWriter pw, String hdr, String sep, java.util.stream.Stream<T> s) { pw.println(s.map(e->""+e).reduce(hdr,(a,b)->a+sep+b)); }
  @SuppressWarnings("unchecked") // from Stackoverflow
  static <T> T[] toA(Collection<T> c, Object e) { return c.toArray((T[])java.lang.reflect.Array.newInstance(e.getClass(), c.size())); }
  static int randN(int range) { return (int)Math.round(Math.random()*range); }
  static void nodeOut(int id, String m) { 
    System.out.println("node" + id + (m = nodes >= 5 ? map(m.split(" "),s->s.startsWith("BL")?s:abbrev("",s,8,20)).reduce("",(a,b)->a+" "+b).trim():m));
  }
  static String txt(Set<String> s) { return Arrays.toString(s.toArray(new String[0])); }
  static boolean fit_p(byte[] hash, final int dif) { // does hash have given difficulty?
    for (int i = 0; i < dif/2/8; i++) if (hash[i] != 0) return false;
    return ((int)hash[dif/2/8] & 0xff) < (1 << (8 - dif%8));
  }
  static String toHex(byte[] data) {
    StringBuilder sb = new StringBuilder();
    for (byte b: data) sb.append(String.format("%02x", b&0xff));
    return sb.toString();
  }
  static String abbrev(String b, String s, int d, int m) { int l=s.length(); return l < m ? s : b+s.substring(0, d)+"..."+s.substring(s.length()-d);}
  static byte[] asHex(String s) { // from stackoverflow
    int len = s.length(); byte[] data = new byte[len / 2];
    for (int i = 0; i < len; i += 2)
      data[i / 2] = (byte)((Character.digit(s.charAt(i), 16) << 4)+ Character.digit(s.charAt(i+1), 16));
    return data;
  }
  static String get(String k, Block b)  { String r=null; for (; b.prev != null && r == null; b = b.prev) r = b.d.get(k); return r; }
  static String gall(String k, Block b) { String v,r=E;  for (; b.prev != null; b = b.prev) if ((v=b.d.get(k))!=null) r+=v; return r; }
  static double toD(String v) { return Double.parseDouble(v); } static int toI(String v) { return Integer .parseInt(v); }
  static String log(PrintWriter log, String f, Object... a) { String m=String.format(f, a); if (log != null) log.println(m); log.flush(); return m; }
  static String logVal(PrintWriter log, String msg, String val) { if(log != null) log.println(msg); return val; }
  static String verifyTx(String tx, int[] fees, MessageDigest md, Block b, Signature s, KeyFactory kf, PrintWriter log) { 
    String a[] = tx.split(" "), h = to58(md.digest(tx.getBytes(UTF_8))), prev = get(a[3], b), preva[]=null; int outN = -1; 
    try { X509EncodedKeySpec eks = new X509EncodedKeySpec(as58(a[4])); int fee;
      s.initVerify(kf.generatePublic(eks)); s.update(tx.substring(0, tx.lastIndexOf(" SIG")).getBytes((UTF_8)));
      if (!s.verify(as58(a[10]))) return logVal(log,"bad signature in " + tx, null);
      if (get(h, b) != null) return logVal(log, "tx previously included in a block, " + tx, null); // make sure none of the new txs are stored in prev blocks!
      if (a[0].equals("MINT")) {
        if (toI(a[5]) != fees[0]+reward) return logVal(log, "coinbase wrong amount "+tx, null); 
      } else { 
        if (prev == null) return logVal(log, "prev tx not found " + tx, null);  else preva = prev.split(" ");
        if (!preva[(outN=toI(a[2]))+1].equals(a[4])) return logVal(log, "in-pk |"+(a[4])+"|and prev tx's out pk |"+preva[outN+1]+"| differ " + tx + " " + Arrays.toString(preva), null); 
        if (get(a[2]+":"+a[3],b) != null) return logVal(log, "input is already spent " + tx, null); 
        if ((fee=toI(preva[outN]) - toI(a[7]) - toI(a[5])) < 0) return logVal(log, "tx src not enough balance" + tx, null); else fees[0]+=fee;
      } // was: acceptTx(tx, h, atr, b.d, b.ht, 5, 7);
      b.d.put(a[2]+":"+a[3],tx); b.d.put(h, tx); for(int i=5;i<=7;i+=2) b.d.put(a[i+1], a[i]+":"+i+":"+h+":"+b.ht+":/"+b.d.getOrDefault(a[i+1],"")); 
    } catch (Exception e) { return logVal(log, e+": verification failed. tx:" + tx, null); } return h;
  }
  static String sign(String msg, PrivateKey sk) throws Exception {
    Signature s = Signature.getInstance("SHA256withECDSA"); s.initSign(sk); s.update(msg.getBytes(UTF_8));
    return msg + " SIG " + to58(s.sign()) + " \n"; // last space is important, see txn.split(" ")!
  }
  static final String ALPH = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"; 
  static final char A1 = ALPH.charAt(0); static final BigInteger A_SZ = BigInteger.valueOf(ALPH.length());
  static String to58_(byte[] data) { // see https://github.com/nayuki/Bitcoin-Cryptography-Library/blob/master/java/io/nayuki/bitcoin/crypto/Base58Check.java
    StringBuilder sb = new StringBuilder();
    for (BigInteger quotrem[], num = new BigInteger(1, data); num.signum() != 0; num = quotrem[0])
      sb.append(ALPH.charAt((quotrem = num.divideAndRemainder(A_SZ))[1].intValue()));
    return sb.reverse().toString();
  }
  static String to58(byte[] data) { // see https://github.com/nayuki/Bitcoin-Cryptography-Library/blob/master/java/io/nayuki/bitcoin/crypto/Base58Check.java
    StringBuilder sb = new StringBuilder();
    for (BigInteger quotrem[], num = new BigInteger(1, data); num.signum() != 0; num = quotrem[0])
      sb.append(ALPH.charAt((quotrem = num.divideAndRemainder(A_SZ))[1].intValue()));
    for (int i = 0; i < data.length && data[i] == 0; i++) sb.append(A1);
    return  sb.reverse().toString();
  }
  static byte[] as58(final String s) throws IOException { // seehttps://github.com/nayuki/Bitcoin-Cryptography-Library/blob/master/java/io/nayuki/bitcoin/crypto/Base58Check.java
    BigInteger n = BigInteger.ZERO;
    for (int d, i = 0; i < s.length(); i++, n = (n.multiply(A_SZ)).add(BigInteger.valueOf(d)))
      d = ALPH.indexOf(s.charAt(i));
    byte[] b = n.toByteArray();  if (b[0] == 0) b = Arrays.copyOfRange(b, 1, b.length);
    ByteArrayOutputStream buf = new ByteArrayOutputStream();
    for (int i = 0; i < s.length() && s.charAt(i) == A1; i++) buf.write(0);
    buf.write(b); return buf.toByteArray();
  }
} // References: [1] Satoshi Nakamoto, "Bitcoin: A Peer-to-Peer Electronic Cash System",2008

// NOTES

// At the moment, TXN words are  timestamp inIdx inTxHash pk amount1 pk1 amount2 pk2 SIG signature
//                                   1       2      3     4    5      6    7      8   9   10

// CHANGES

// 1. Bye-bye doubles! as soon as fees were added and verified,
// doubles no longer work. Switched to  milliBTC.

// 2. verifyTx now calls acceptTx, this helps miner to detect conflicting txns in new batch,
// for which a fresh block is constructed with a dictionary.


// TODO and ideas

// With the block size fixed and limited (16 or 32k or so) the step of
// transaction verification in miner threads should include logic for
// reducing the batch to fit.  The miner can gain in reward if before
// the transaction are pruned, they are ordered using fee per byte
// factor. Method verifyTx can return class Tx {boolean ok; int fee; int len; String txt;}
// and 
//
// txs = seq(scratch.txns).filter(t->null!=verifyTx(t,fee,md,b,sig,kf,log)).reduce("",(x,y)->x+", "+y));
// 
// becomes 
//
// int fees = 0; String txs = "";
// for (Tx tx : seq(scratch.txns).map(t->verifyTx(t,md,b,sig,kf,log)).filter(t->t.ok)
//              .sort((t1, t2)->1000*t1.fee/t1.len - 1000*t2.fee/t2.len);
//   { if (txs.length + tx.len > TXLMX) break; fees+=tx.fee; txs+=tx.txt; }

// As transactions verification in miner threads now includes accepting
// transactions into some b.d, question is what to do with those that
// fail verification. Mark them as bad or even remove from scratch.d
// or re-try again each time?  The later happens now with some time
// wasted on it. Advantage is that if forking rearranges the chain, no
// bookkeeping is required. Ideally, if the 'cause' of rejection is
// some txn that is N blocks deep (3 is good enough) then such txn can
// be removed from scratch.d. it looks as only those that depend on
// txn in the same or 2 blocks can be kept. Those with bad signatures,
// bad balance, bad tx hash etc etc can be permanently removed.

// In listeners, block verification needs to include hashing the
// transactions and doing
//
// if (!toHex(md.digest(prv+root+form("%x08",nonce)).getBytes(UTF_8))).equals(hash)) { out("Verification FAILED, block hash is wrong: " + hash); continue; }

// Height. Add blockchain 'height' index in each block or perhaps a
// simple loop to get it. height(b) -> int with -1, -2, -3 etc meaning
// block has broken link that deep.

// Maybe...Coinbase transactions probably should award to a new pk. currenty
// 3rd and 6th fields are the same pk

// Asking. node must be able to ask the network about a missing block
// or get the whole chain.  What about the asking node switching to a
// separate channel, or better, spawning a special thread to collect
// the responses?

// Maybe...The 'top set' concept. A node maintains a list of tops each leading to
// the same root (zero block) each being verified and containing valid
// txns. if there is more than one, and all of the same height, then
// node is not yet able to find the longest chain. txn count does not
// matter. longest chain wins.  Q: should the other ones (shorter) be
// immediately flashed or kept just in case? Maybe the later is more
// interesting.

// possibly, review and improve the 'spent out' detection. currently -
// pk is marked 'spent' in a block.d.

// multiple processes: late-comer must name the nodes (or at least,
// files) differently, how? simple hack: asking. asking the net about
// the value of 'nodes' and start from there.  simplest solution is
// cluster name: java -Dcluster=SF java -Dcluster=MY java
// -Dcluster=LA. Yet even simpler to run each cluster in a separate
// 'home' dir.

// Command line options: perhaps, switch from args[] to props:
// CryptoBlockChain -Dn=7 -Dd=49 -Dcoin=XYZCoin ....  int difficulty =
// toI(sprop("d","48")), nodes = toI(sprop("n", "7")

// Streams: byte stream does not work static String toHex2(byte[] d) {
// return Arrays.stream(d).map(b->String.format("%02x",
// b&0xff)).reduce("",(a,b)->a+b); }
