package store

import "time"

type User struct {
	ID            int64
	Username      string
	PasswordHash  string
	TOTPSecretEnc []byte
	TOTPLastUsed  int64
	Role          string
}

const userCols = `id, username, password_hash, totp_secret_enc, totp_last_used, role`

func scanUser(row scanner) (*User, error) {
	var u User
	if err := row.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.TOTPSecretEnc, &u.TOTPLastUsed, &u.Role); err != nil {
		return nil, err
	}
	return &u, nil
}

func (s *Store) CreateUser(u *User) error {
	res, err := s.db.Exec(`INSERT INTO users (username, password_hash, totp_secret_enc, totp_last_used, role, created_at) VALUES (?,?,?,?,?,?)`,
		u.Username, u.PasswordHash, u.TOTPSecretEnc, u.TOTPLastUsed, u.Role, time.Now().Unix())
	if err != nil {
		return err
	}
	u.ID, _ = res.LastInsertId()
	return nil
}

func (s *Store) UpdateUser(u *User) error {
	_, err := s.db.Exec(`UPDATE users SET username=?, password_hash=?, totp_secret_enc=?, totp_last_used=?, role=? WHERE id=?`,
		u.Username, u.PasswordHash, u.TOTPSecretEnc, u.TOTPLastUsed, u.Role, u.ID)
	return err
}

func (s *Store) UserByName(name string) (*User, error) {
	return scanUser(s.db.QueryRow(`SELECT `+userCols+` FROM users WHERE username=?`, name))
}

func (s *Store) UserByID(id int64) (*User, error) {
	return scanUser(s.db.QueryRow(`SELECT `+userCols+` FROM users WHERE id=?`, id))
}

func (s *Store) ListUsers() ([]User, error) {
	rows, err := s.db.Query(`SELECT ` + userCols + ` FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *u)
	}
	return out, rows.Err()
}

func (s *Store) DeleteUser(id int64) error {
	_, err := s.db.Exec(`DELETE FROM users WHERE id=?`, id)
	return err
}

func (s *Store) CountAdmins() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT count(*) FROM users WHERE role='admin'`).Scan(&n)
	return n, err
}
