// SA-JAVA-05: Safe SQL using PreparedStatement
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

public class UserRepository {
    private final Connection connection;

    public UserRepository(Connection connection) {
        this.connection = connection;
    }

    public ResultSet findByName(String username) throws Exception {
        PreparedStatement pstmt = connection.prepareStatement(
            "SELECT * FROM users WHERE name = ?");
        pstmt.setString(1, username);
        return pstmt.executeQuery();
    }
}
