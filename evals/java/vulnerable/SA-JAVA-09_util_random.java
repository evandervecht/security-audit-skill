// SA-JAVA-09: Insecure random using java.util.Random
import java.util.Random;

public class TokenGenerator {
    private final Random random = new Random();

    public String generateSessionToken() {
        return Long.toHexString(random.nextLong())
             + Long.toHexString(random.nextLong());
    }
}
