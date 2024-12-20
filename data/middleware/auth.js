const jwt = require("jsonwebtoken");
const jwtSecret =
  process.env.JWT_SECRET ||
  "4715aed3c946f7b0a38e6b534a9583628d84e96d10fbc04700770d572af3dce43625dd";

function authenticateToken(req, res, next) {
  // Ensure cookies are available
  if (!req.cookies || !req.cookies.token) {
    console.warn("No token found in cookies");
    return res.redirect("/user/login");
  }

  const token = req.cookies.token;

  // Verify the token
  jwt.verify(token, jwtSecret, (err, decoded) => {
    if (err) {
      console.error("Token verification failed:", {
        message: err.message,
        name: err.name,
        stack: err.stack,
      });

      if (err.name === "TokenExpiredError") {
        return res.redirect("/user/login?error=expired");
      }

      return res.redirect("/user/login");
    }

    // Store decoded user information
    req.user = decoded.user;
    next(); // Proceed to the next middleware or route handler
  });
}

module.exports = authenticateToken;
