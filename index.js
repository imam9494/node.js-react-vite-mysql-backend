require("dotenv").config();

const express = require("express");
const cors = require("cors");

const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const verifyAdmin = require("./middleware/verifyAdmin");

const verifyToken = require("./middleware/verifyToken");

const db = require("./db");

const app = express();
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET;


app.use(cors());
app.use(express.json());

app.use((req, res, next) => {
    console.log(req.method, req.url);
    next();
});

// ==================== GET ====================
// ==================== GET ====================

// ==================== GET ====================

app.get(
  "/api/v1/users",
  verifyToken,
  async (req, res) => {
    try {
      const [rows] = await db.query("SELECT * FROM users");
      res.json(rows);
    } catch (err) {
      console.error(err);
      res.status(500).json({ message: err.message });
    }
  }
);




// ==================== POST ====================


app.post(
    "/api/v1/users",
    verifyToken,
    verifyAdmin,
    async (req, res) => {
    try {
        const { name, email, password, role } = req.body;

        if (!name || !email || !password || !role) {
            return res.status(400).json({
                message: "Semua field wajib diisi",
            });
        }

        if (password.length < 6) {
            return res.status(400).json({
                message: "Password minimal 6 karakter",
            });
        }
        console.log("BODY:", req.body);
        console.log("PASSWORD:", password);



        console.log("CEK EMAIL:", email);
        const [existingUser] = await db.query(
            "SELECT id FROM users WHERE email = ?",
            [email]
        );

        if (existingUser.length > 0) {
            return res.status(400).json({
                message: "Email sudah terdaftar"
            });
        }
        const hashedPassword = await bcrypt.hash(password, 10);

        await db.query(
            "INSERT INTO users (name,email,password,role) VALUES (?,?,?,?)",
            [name, email, hashedPassword, role]
        );

        res.json({
            message: "User berhasil ditambahkan",
        });

    } catch (err) {
        console.error(err);

        res.status(500).json({
            message: err.message,
        });
    }
});

// ==================== PUT ====================
// ==================== PUT ====================
app.put(
    "/api/v1/users/:id",
    verifyToken,
    verifyAdmin,
    async (req, res) => {
        try {
            const { id } = req.params;
            const { name, email, password, role } = req.body;
const [existingUser] = await db.query(
    "SELECT id FROM users WHERE email = ? AND id <> ?",
    [email, id]
);

if (existingUser.length > 0) {
    return res.status(400).json({
        message: "Email sudah digunakan user lain",
    });
}
            if (password) {

                const hashedPassword = await bcrypt.hash(password, 10);

                await db.query(
                    "UPDATE users SET name=?, email=?, password=?, role=? WHERE id=?",
                    [name, email, hashedPassword, role, id]
                );

            } else {

                await db.query(
                    "UPDATE users SET name=?, email=?, role=? WHERE id=?",
                    [name, email, role, id]
                );

            }

            res.json({
                message: "User berhasil diupdate",
            });

        } catch (err) {
            console.error(err);
            res.status(500).json({
                message: err.message,
            });
        }
    }
);

// ==================== DELETE ====================

app.delete(
  "/api/v1/users/:id",
  verifyToken,
  verifyAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;

      await db.query(
        "DELETE FROM users WHERE id=?",
        [id]
      );

      res.json({
        message: "User berhasil dihapus",
      });

    } catch (err) {
      console.error(err);

      res.status(500).json({
        message: err.message,
      });
    }
  }
);
// ==================== LOGIN ====================

app.post("/api/v1/login", async (req, res) => {
    try {

        const { email, password } = req.body;

        const [rows] = await db.query(
            "SELECT * FROM users WHERE email=?",
            [email]
        );

        if (rows.length === 0) {
            return res.status(401).json({
                message: "Email atau password salah",
            });
        }

        const user = rows[0];

        const cocok = await bcrypt.compare(
            password,
            user.password
        );

        if (!cocok) {
            return res.status(401).json({
                message: "Email atau password salah",
            });
        }

        const accessToken = jwt.sign(
            {
                id: user.id,
                email: user.email,
                role: user.role,
            },
            JWT_SECRET,
            {
                expiresIn: "15m",
            }
        );

        const refreshToken = jwt.sign(
            {
                id: user.id,
            },
            JWT_REFRESH_SECRET,
            {
                expiresIn: "7d",
            }
        );

        await db.query(
            "UPDATE users SET refresh_token=?, last_login=NOW() WHERE id=?",
            [refreshToken, user.id]
        );

        res.json({
            message: "Login berhasil",
            accessToken,
            refreshToken,
            user,
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({
            message: err.message,
        });
    }
});
app.post("/api/v1/refresh", async (req, res) => {
    try {
        const { refreshToken } = req.body;

        if (!refreshToken) {
            return res.status(401).json({
                message: "Refresh token tidak ada",
            });
        }

        const [rows] = await db.query(
            "SELECT * FROM users WHERE refresh_token=?",
            [refreshToken]
        );

        if (rows.length === 0) {
            return res.status(403).json({
                message: "Refresh token tidak valid",
            });
        }

        jwt.verify(
            refreshToken,
            JWT_REFRESH_SECRET,
            (err, decoded) => {

                if (err) {
                    return res.status(403).json({
                        message: "Refresh token expired",
                    });
                }

                const accessToken = jwt.sign(
                    {
                        id: decoded.id,
                        email: rows[0].email,
                        role: rows[0].role,
                    },
                    JWT_SECRET,
                    {
                        expiresIn: "15m",
                    }
                );

                res.json({
                    accessToken,
                });

            }
        );

    } catch (err) {
        console.error(err);
        res.status(500).json({
            message: err.message,
        });
    }
});


app.post("/api/v1/refresh", async (req, res) => {
    try {

        const { refreshToken } = req.body;

        if (!refreshToken) {
            return res.status(401).json({
                message: "Refresh token tidak ditemukan",
            });
        }

        const [rows] = await db.query(
            "SELECT * FROM users WHERE refresh_token = ?",
            [refreshToken]
        );

        if (rows.length === 0) {
            return res.status(403).json({
                message: "Refresh token tidak valid",
            });
        }

        jwt.verify(
            refreshToken,
            JWT_REFRESH_SECRET,
            (err, decoded) => {

                if (err) {
                    return res.status(403).json({
                        message: "Refresh token expired",
                    });
                }

                const accessToken = jwt.sign(
                    {
                        id: rows[0].id,
                        email: rows[0].email,
                        role: rows[0].role,
                    },
                    JWT_SECRET,
                    {
                        expiresIn: "15m",
                    }
                );

                res.json({
                    accessToken,
                });

            }
        );

    } catch (err) {

        console.error(err);

        res.status(500).json({
            message: err.message,
        });

    }
});

app.post("/api/v1/logout", verifyToken, async (req, res) => {
    try {

        await db.query(
            "UPDATE users SET refresh_token = NULL WHERE id = ?",
            [req.user.id]
        );

        res.json({
            message: "Logout berhasil"
        });

    } catch (err) {

        console.error(err);

        res.status(500).json({
            message: err.message
        });

    }
});

app.put("/api/v1/change-password", verifyToken, async (req, res) => {
    try {

        const { oldPassword, newPassword } = req.body;

        const [rows] = await db.query(
            "SELECT password FROM users WHERE id = ?",
            [req.user.id]
        );

        if (rows.length === 0) {
            return res.status(404).json({
                message: "User tidak ditemukan"
            });
        }

        const match = await bcrypt.compare(
            oldPassword,
            rows[0].password
        );

        if (!match) {
            return res.status(400).json({
                message: "Password lama salah"
            });
        }

        const hash = await bcrypt.hash(newPassword, 10);

        await db.query(
            "UPDATE users SET password = ? WHERE id = ?",
            [hash, req.user.id]
        );

        res.json({
            message: "Password berhasil diubah"
        });

    } catch (err) {
        console.log("USER:", req.user);
        console.log("BODY:", req.body);
        console.error(err);

        res.status(500).json({
            message: err.message
        });

    }
});
app.listen(3000, () => {
    console.log("Server running on http://localhost:3000");
});
