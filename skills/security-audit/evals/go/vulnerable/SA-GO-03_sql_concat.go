package main

// SA-GO-03: SQL injection via string concatenation
import "fmt"

func getUser(db *sql.DB, name string) (*User, error) {
	query := fmt.Sprintf("SELECT id, email FROM users WHERE name = '%s'", name)
	row := db.QueryRow(query)
	var u User
	err := row.Scan(&u.ID, &u.Email)
	return &u, err
}
