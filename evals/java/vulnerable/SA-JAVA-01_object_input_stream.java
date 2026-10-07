// SA-JAVA-01: Insecure deserialization via ObjectInputStream
import java.io.ObjectInputStream;
import javax.servlet.http.HttpServletRequest;

public class DataImporter {
    public Object importData(HttpServletRequest request) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(request.getInputStream());
        return ois.readObject();
    }
}
