const mysql = require("mysql2");

const pool = mysql.createPool({
  host: "localhost",
  user: "appuser",
  password: "app123",
  database: "auth_app",
});

module.exports = pool.promise();
