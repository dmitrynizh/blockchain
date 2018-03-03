//
// This is a demo for stream-based map/reduce operations with wallet and tx output tecords
//
// At Sat Mar 03 07:02:49 PST 2018 my balance: 80.000 
// At Sat Mar 03 07:02:49 PST 2018 my balance: 225.000 
// At Sat Mar 03 07:02:49 PST 2018 my balance: 175.000 
// At Sat Mar 03 07:02:49 PST 2018 my balance: 105.000 
// 
// Wallet balances
// you have available: 10.0 20.0 on key bbbbbb.
// you have available: 50.0 on key cccccc.
// you have available: 25.0 on key dddddd.
// 
// Spending history
// you spent|redeemed: 50.0 on key aaaaaa.
// you spent|redeemed: 70.0 on key dddddd.
//

import java.util.*; 
import java.io.*; 
import java.util.stream.*; 
import java.util.function.*; 
import java.security.*;
public class Streams { // (c) 2018 dmitrynizh. MIT License.
  static class Block { Block prev; HashMap<String,String>d;}
  static class Cred { String pk; PrivateKey sk; Cred(String p, PrivateKey s) {pk=p;sk=s;}} 
  static final String E = "";
  public static void main(String[] args) { // run demo
    try (PrintWriter bpw = new PrintWriter(System.out)) {

        // create chain of blocks
        Block zero = new Block(); zero.d = new HashMap<>();  
        Block b1 = new Block(); b1.prev = zero; b1.d = new HashMap<>();  
        Block b2 = new Block(); b2.prev = b1;   b2.d = new HashMap<>();  
        Block s =  new Block(); s.prev = b2;    s.d  = new HashMap<>();  

        // create wallet
        Vector<Cred> w = new Vector<>();
        // populate wallet with keys
        w.add(new Cred("aaaaaa", null));
        w.add(new Cred("bbbbbb", null));
        w.add(new Cred("cccccc", null));
        w.add(new Cred("dddddd", null));

        // let the wallet contain some UTxOs amount:OId:Txhash:height/*
        b1.d.put("aaaaaa","50.0:5:asdfeds:1:/");
        b1.d.put("bbbbbb","20.0:5:dfsfsdf:1:/");
        b2.d.put("bbbbbb","10.0:5:ytytytu:1:/");

        printTotalBalance(bpw, s, w); // how much I have unspent?

        // add some more UTXOs
        b2.d.put("cccccc","50.0:7:unvhdyg:2:/");
        b1.d.put("dddddd","70.0:5:dhdyrmf:1:/25.0:7:sefyrmf:2:/");

        printTotalBalance(bpw, s, w); // how much I have?

        // spend some. this marks TxO n:txhash as 'spent'
        b1.d.put("5:asdfeds", "ytuytuyhg");
        printTotalBalance(bpw, s, w);

        // spend more
        b2.d.put("5:dhdyrmf", "oppkjdsdf");
        printTotalBalance(bpw, s, w);

        // summary
        log(bpw, "\nWallet balances\n", "", 
            map(w,c->gall(c.pk,s)+" on key "+c.pk+".\n: : :").filter(st->!st.startsWith(" on"))
            .map(st->map(st.split("/"),e->e.split(":"))
                 .filter(r->r[0].charAt(0)==' '||get(r[1]+":"+r[2],s)==null).map(a->a[0]).reduce("you have available: ",(a,b)->a+" "+b))
            .map(v->v.replaceAll(" +", " ")).filter(v->v.indexOf(": on")<0));
        log(bpw, "Spending history\n", "", 
            map(w,c->gall(c.pk,s)+" on key "+c.pk+".\n: : :").filter(st->!st.startsWith(" on"))
            .map(st->map(st.split("/"),e->e.split(":"))
                 .filter(r->r[0].charAt(0)==' '||get(r[1]+":"+r[2],s)!=null).map(a->a[0]).reduce("you spent|redeemed: ",(a,b)->a+" "+b))
            .map(v->v.replaceAll(" +", " ")).filter(v->v.indexOf(": on")<0));
      } catch (Exception ex) { ex.printStackTrace(); }
  }

  static void printTotalBalance(PrintWriter bpw, Block b, Vector<Cred> w) {
    double sum = map(w,c->gall(c.pk,b)).filter(v->v!=E)
      .mapToDouble(s->map(s.split("/"),v->v.split(":"))
                   .filter(v->get(v[1]+":"+v[2],b)==null)
                   .mapToDouble(v->toD(v[0])).sum()).sum();
    bpw.printf("At %tc my balance: %.3f \n", new Date(), sum); bpw.flush();
  }

  static String get(String k, Block b)  { String r=null; for (; b.prev != null && r == null; b = b.prev) r = b.d.get(k); return r; }
  static String gall(String k, Block b) { String v,r=E;  for (; b.prev != null; b = b.prev) if ((v=b.d.get(k))!=null) r+=v; return r; }
  static double toD(String v) { return Double.parseDouble(v); } 
  static int    toI(String v) { return Integer .parseInt(v);  }

  // no generics helper
  static Stream<Cred> sCred(Collection<Cred> c) { return c.stream(); }
  // this one makes the above not needed.
  static <T>   Stream<T> seq(Collection<T> c)   { return c.stream(); }
  // saves space in long map-reduce chains
  static <T>   Stream<T> seq(T[] a) { return Arrays.stream(a); }

  // same
  static <X,Y> Stream<Y> map(X[] a,          Function<? super X,? extends Y> f) { return seq(a).map(f); }
  static <X,Y> Stream<Y> map(Collection<X>c, Function<? super X,? extends Y> f) { return seq(c).map(f); }

  // top-level consumer which is concatenator reducer-printer
  static <T> void log(PrintWriter pw, String hdr, String sep, Stream<T> s) { pw.println(s.map(e->""+e).reduce(hdr,(a,b)->a+sep+b)); }

  // saves space in long map-reduce chains
  @SuppressWarnings("unchecked") // from Stackoverflow
  static <T> T[] toA(Collection<T> c) { return c.toArray((T[])java.lang.reflect.Array.newInstance(c.getClass(), c.size())); }

}


