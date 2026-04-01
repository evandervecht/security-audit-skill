// SA-JAVA-03: Safe JNDI usage with allowlist validation
import javax.naming.Context;
import java.util.Set;

public class ResourceLocator {
    private static final Set<String> ALLOWED = Set.of(
        "java:comp/env/jdbc/primary",
        "java:comp/env/jdbc/replica"
    );

    private final Context context;

    public ResourceLocator(Context context) {
        this.context = context;
    }

    public Object findResource(String name) throws Exception {
        if (!ALLOWED.contains(name)) {
            throw new SecurityException("Disallowed JNDI name: " + name);
        }
        return context.lookup(name);
    }
}
