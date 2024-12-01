const jwt = require('jsonwebtoken');
const dotenv = require("dotenv");
dotenv.config();

const verifyAccessToken = async (req, res, next) => {
    const authHeader = req.headers['authorization'];

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(403).json({
            message: "Access Denied! Missing or malformed token.",
            status: 403,
            success: false,
        });
    }

    const token = authHeader.split(" ")[1];

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        if (!decoded.userId) {
            return res.status(403).json({
                message: "Invalid Token. User ID missing.",
                status: 403,
                success: false,
            });
        }

        req.userId = decoded.userId;
        next(); 
    } catch (error) {
        console.log("Token verification error:", error.message);
        return res.status(500).json({
            message: "Internal server error. Please try again later.",
            status: 500,
            success: false,
            error: error.message,
        });
    }
};

module.exports = verifyAccessToken;