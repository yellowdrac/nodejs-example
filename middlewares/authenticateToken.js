const jwt = require('jsonwebtoken');
const { ACCESS_TOKEN_SECRET, ACCESS_TOKEN_EXPIRY, REFRESH_TOKEN_SECRET, REFRESH_TOKEN_EXPIRY } = process.env;
// Middleware de autenticación
function authenticateToken(req, res, next) {

    const token = req.headers['authorization'];

    const tokenSinBearer = token.substring(7); // Comienza desde el índice 7 para omitir "Bearer "

    if (!tokenSinBearer) {
        return res.status(401).send('Access denied. Token missing.');
    }

    jwt.verify(tokenSinBearer, ACCESS_TOKEN_SECRET, (err, decoded) => {
        if (err) {
            if (err.name === 'TokenExpiredError') {
                console.log('Access denied. Token expired.');
                return res.status(401).send('Access denied. Token expired.');
            } else {
                return res.status(403).send('Access denied. Invalid token.');
            }
        }
        req.user = decoded;
        next();
    });
}

module.exports = authenticateToken;