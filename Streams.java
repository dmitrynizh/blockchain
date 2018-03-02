//
// This is a demo for stream-based map/reduce operations with wallet components.
//
//  $ javac Streams.java
//  $ javac Streams.java ; java Streams
//  At <date> my balance: 60.000 
//  At <date> my balance: 180.000 
//  At <date> my balance: 130.000 
//  At <date> my balance: 60.000 
//  
//  Wallet ballances
//  you have available: 10.0 20.0 on key bbbbbb.
//  you have available: 50.0 on key cccccc.
//  
//  
//  Spending history
//  you spent|redeemed: 50.0 on key aaaaaa.
//  you spent|redeemed: 70.0 on key dddddd.
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
  public static void main(String[] args) { // run network
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

        // have some UTXOs
        b1.d.put("aaaaaa","50.0:5:asdfeds:1:/");
        b1.d.put("bbbbbb","20.0:5:dfsfsdf:1:/");
        b2.d.put("bbbbbb","10.0:5:ytytytu:1:/");

        printTotalBalance(bpw, s, w); // how much I have unspent?

        b2.d.put("cccccc","50.0:5:unvhdyg:3:/");
        b1.d.put("dddddd","70.0:5:dhdyrmf:3:/");

        printTotalBalance(bpw, s, w); // how much I have?

        // spend some
        b1.d.put("5:asdfeds", "xyz");
        printTotalBalance(bpw, s, w);

        // spend more
        b2.d.put("5:dhdyrmf", "xyz");
        printTotalBalance(bpw, s, w);

        log(bpw, "\nWallet ballances\n", "", 
            map(w,c->gall(c.pk,s)+" on key "+c.pk+".\n: : :").filter(st->!st.startsWith(" on"))
            .map(st->map(st.split("/"),e->e.split(":"))
                 .filter(r->r[0].charAt(0)==' '||get(r[1]+":"+r[2],s)==null).map(a->a[0]).reduce("you have available: ",(a,b)->a+" "+b))
            .map(v->v.replaceAll(" +", " ")).filter(v->v.indexOf(": on")<0));
        log(bpw, "\nSpending history\n", "", 
            map(w,c->gall(c.pk,s)+" on key "+c.pk+".\n: : :").filter(st->!st.startsWith(" on"))
            .map(st->map(st.split("/"),e->e.split(":"))
                 .filter(r->r[0].charAt(0)==' '||get(r[1]+":"+r[2],s)!=null).map(a->a[0]).reduce("you spent|redeemed: ",(a,b)->a+" "+b))
            .map(v->v.replaceAll(" +", " ")).filter(v->v.indexOf(": on")<0));
      } catch (Exception ex) { ex.printStackTrace(); }
  }

  static void printTotalBalance(PrintWriter bpw, Block b, Vector<Cred> w) {
    double sum = map(w,c->get(c.pk,b)).filter(v->v!=null)
      .mapToDouble(s->map(s.split("/"),v->v.split(":"))
                   .filter(v->get(v[1]+":"+v[2],b)==null)
                   .mapToDouble(v->toD(v[0])).sum()).sum();
    bpw.printf("At %tc my balance: %.3f \n", new Date(), sum); bpw.flush();
  }

  static Stream<Cred> sCred(Collection<Cred> c) { return c.stream(); }
  static <T>   Stream<T> seq(Collection<T> c) { return c.stream(); }
  static <T>   Stream<T> seq(T[] a) { return Arrays.stream(a); }
  static <X,Y> Stream<Y> map(X[] a, Function<? super X,? extends Y> mapper) { return Arrays.stream(a).map(mapper); }
  static <X,Y> Stream<Y> map(Collection<X>c, Function<? super X,? extends Y> f) { return c.stream().map(f); }
  static <T> void log(PrintWriter pw, String hdr, String sep, Stream<T> s) { pw.println(s.map(e->""+e).reduce(hdr,(a,b)->a+sep+b)); }

  @SuppressWarnings("unchecked") // from Stackoverflow
  static <T> T[] toA(Collection<T> c) { return c.toArray((T[])java.lang.reflect.Array.newInstance(c.getClass(), c.size())); }

  static String get(String k, Block b)  { String r=null; for (; b.prev != null && r == null; b = b.prev) r = b.d.get(k); return r; }
  static String gall(String k, Block b) { String v,r="";  for (; b.prev != null; b = b.prev) if ((v=b.d.get(k))!=null) r+=v; return r; }
  static double toD(String v) { return Double.parseDouble(v); } static int toI(String v) { return Integer .parseInt(v); }
}

// NOTES

