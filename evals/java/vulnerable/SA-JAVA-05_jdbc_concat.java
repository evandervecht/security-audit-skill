// SA-JAVA-05: SQL injection via JDBC string concatenation
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;

public class UserRepository {
    private final Connection connection;

    public UserRepository(Connection connection) {
        this.connection = connection;
    }

    public ResultSet findByName(String username) throws Exception {
        Statement stmt = connection.createStatement();
        return stmt.executeQuery("SELECT * FROM users WHERE name = '" + username + "'");
    }
}
