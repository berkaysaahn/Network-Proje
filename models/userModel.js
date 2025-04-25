const pool = require("../db");

// Kullanıcıyı e-posta ile bul
const findUserByEmail = async (email) => {
  const query = `SELECT * FROM users WHERE email = $1`;
  const { rows } = await pool.query(query, [email]);
  return rows[0];
};

// Yeni kullanıcı oluştur
const createUser = async (name, email, hashedPassword) => {
  const query = `INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING *`;
  const values = [name, email, hashedPassword];
  const { rows } = await pool.query(query, values);
  return rows[0];
};

module.exports = { createUser, findUserByEmail };

