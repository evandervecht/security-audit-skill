// SA-CS-03: Safe SQL using FromSqlInterpolated (auto-parameterized)
using Microsoft.EntityFrameworkCore;

public class UserRepository
{
    private readonly AppDbContext _context;

    public UserRepository(AppDbContext context) => _context = context;

    public List<User> FindByName(string username)
    {
        return _context.Users
            .FromSqlInterpolated($"SELECT * FROM Users WHERE Username = {username}")
            .ToList();
    }
}
