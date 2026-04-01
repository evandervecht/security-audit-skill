// SA-CS-03: SQL injection via FromSqlRaw with interpolation
using Microsoft.EntityFrameworkCore;

public class UserRepository
{
    private readonly AppDbContext _context;

    public UserRepository(AppDbContext context) => _context = context;

    public List<User> FindByName(string username)
    {
        return _context.Users
            .FromSqlRaw($"SELECT * FROM Users WHERE Username = '{username}'")
            .ToList();
    }
}
