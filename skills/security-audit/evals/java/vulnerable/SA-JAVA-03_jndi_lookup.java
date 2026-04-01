// SA-JAVA-03: JNDI injection via InitialContext.lookup
import javax.naming.InitialContext;
import javax.servlet.http.HttpServletRequest;

public class ResourceLocator {
    public Object findResource(HttpServletRequest request) throws Exception {
        String name = request.getParameter("resource");
        InitialContext ctx = new InitialContext();
        return ctx.lookup(name);
    }
}
