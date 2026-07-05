function verifyAdmin(req, res, next) {
  if (req.user.role !== "admin") {
    return res.status(403).json({
      message: "Akses ditolak. Hanya Admin.",
    });
  }

  next();
}

module.exports = verifyAdmin;
