import java.io.ObjectInputStream;
import java.lang.Runtime;
class App { void run(String x) throws Exception { Runtime.getRuntime().exec(x); ObjectInputStream in; java.util.Random r = new java.util.Random(); } }
