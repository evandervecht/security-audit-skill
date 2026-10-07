// SA-JAVA-01: Safe deserialization using Jackson JSON
import com.fasterxml.jackson.databind.ObjectMapper;
import javax.servlet.http.HttpServletRequest;

public class DataImporter {
    private final ObjectMapper mapper = new ObjectMapper();

    public UserDto importData(HttpServletRequest request) throws Exception {
        return mapper.readValue(request.getInputStream(), UserDto.class);
    }
}
