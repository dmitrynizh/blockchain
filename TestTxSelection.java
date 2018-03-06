import java.util.*;
public class TestTxSelection {
  static class Tx {String hash; int fee; int len; String txt; boolean ok; int v;
    public String toString() {return String.format("%s %d %d %b %d %s", hash, fee, len, ok, v, txt); }};
  static int randN(int range) { return (int)Math.round(Math.random()*range); }
  static String[] sideffect() { System.out.println("-- ttt: "); return new String[] {"a", "b", "c"};  }

  public static void main(String argv[]) {
    int len = 20; Tx a[]  = new Tx[len]; 
    for (int i = 0; i < len; i++) {
      Tx t = new Tx(); a[i] = t;
      t.hash = randomWord(20);  t.txt = "TXN " + randomWord(20) + randomText(20+randN(80));
      t.fee = randN(100); t.len = t.txt.length(); t.ok = randN(1) == 0;
      t.v = randN(12)-6; if (Math.abs(t.v) > 3) t.v = 0; // motly valid, plus -3 -2 -1 1 2 3
    }

    // side effects in for (x:sideffect())
    // for (String s : sideffect())  System.out.println("-- s: " + s);

    // 1. simple sort by 
    Arrays.sort(a, (t1, t2)-> 1000*t1.fee/t1.len - 1000*t2.fee/t2.len);
    System.out.println("-- a: " + Arrays.toString(a).replace(", ", "\n"));


    // 2. prune ok != true,   collect fees, watch for MAX
    { int fees=0, MAX = 500; String txs = "";
      for (Tx tx : Arrays.stream(a).filter(t->t.ok)
             .sorted((t1, t2)->1000*t1.fee/t1.len - 1000*t2.fee/t2.len).toArray(Tx[]::new))
        { if (txs.length() + tx.len > MAX) break; fees+=tx.fee; txs+="\n<"+tx.txt+">"; } 
      System.out.println(" fees: " + fees);
      System.out.println(" txs: " + txs);
    }

    // 3  prune v != 0, collect fees, watch for MAX, add to removed v != 1
    { int fees=0, MAX = 500; String txs = "", removed = "";
      // for (Tx tx : Arrays.stream(a).sorted((t1, t2)->1000*t1.fee/t1.len - 1000*t2.fee/t2.len).toArray(Tx[]::new)) {
      Arrays.sort(a, (t1, t2)->1000*t1.fee/t1.len - 1000*t2.fee/t2.len);
      for (Tx tx : a)
        if (tx.v == 0 && txs.length() + tx.len < MAX) { fees+=tx.fee; txs+="\n<"+tx.txt+">";  }
        else if (tx.v < 0 || tx.v > 1) removed +="\n<"+tx.txt+">"; 
      System.out.println(" fees: " + fees);
      System.out.println(" txs: " + txs);
      System.out.println(" removed: " + removed);
    }

  }

  static final String A58s = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz", T68s = A58s + ".,!?      ";
  static final char[] A58 = A58s.toCharArray(), T68 = T68s.toCharArray();
  static String randomWord(int len) { 
    Random r = new Random(); 
    StringBuilder sb = new StringBuilder(len);
    for(int i = 0; i < len; i++) sb.append(A58[r.nextInt(58)]);
    return sb.toString();
  }
  static String randomText(int len) { 
    Random r = new Random(); 
    StringBuilder sb = new StringBuilder(len);
    for(int i = 0; i < len; i++) sb.append(T68[r.nextInt(68)]);
    return sb.toString();
  }
}

// Notes: this is some new code testing for CryptoBlockChain

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
//              .sorted((t1, t2)->1000*t1.fee/t1.len - 1000*t2.fee/t2.len).toArray[Tx[]::new))
//   { if (txs.length() + tx.len > TXLMX) break; fees+=tx.fee; txs+=tx.txt; }

// As transactions verification in miner threads now includes
// accepting transactions into some b.d, question is what to do with
// those that fail verification. Mark them as bad or even remove from
// scratch.d or re-try again each time?  The later happens now with
// some time wasted on it. Advantage is that if forking rearranges the
// chain, no bookkeeping is required. Ideally, if the 'cause' of
// rejection is some txn that is N blocks deep (3 is good enough) then
// such txn can be removed from scratch.d. it looks as only those that
// depend on txn in the same or 2 blocks can be kept. Those with bad
// signatures, bad balance, bad tx hash etc etc can be permanently
// removed.  This can probably be done with the class Tx shown above
// with 'ok' being int and filtering removed and ok==0 set for valid
// TX with UO, 1 for SO depth 1, 2 for depth 2 and so on.  The for
// loop then does the following 3 things: accumulates valid txs with
// UOs, removes from scratch invlid ones with ok < 0 or ok > depth
// threshold and keeps the rest. here is for depth 1:
//
// for (Tx tx : seq(scratch.txns).map(t->verifyTx(t,md,b,sig,kf,log))
//              .sorted((t1, t2)->1000*t1.fee/t1.len - 1000*t2.fee/t2.len).toArray[Tx[]::new)) {
//   if (t.ok == 0 && txs.length() + tx.len < TXLMX) { fees+=tx.fee; txs+=tx.txt; }
//   else if (t.ok < 0 || t.ok > 1) scratch.txns.remove(t.txt); }

