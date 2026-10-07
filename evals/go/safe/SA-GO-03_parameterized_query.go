package main

// SA-GO-03: Safe parameterized SQL query
func getUser(db *sql.DB, name string) (*User, error) {
	row := db.QueryRow("SELECT id, email FROM users WHERE name = $1", name)
	var u User
	err := row.Scan(&u.ID, &u.Email)
	return &u, err
}
