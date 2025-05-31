/*
 ! Everytime we use a refreshToken to regenerate a new accessToken.
 ? Our refreshToken also gets regenerated, so we gotta save both new tokens.   
 * By Convention, accessToken to be be stored into Headers and refreshTokens
 * to be stored into cookies via cookie-parser.
 */
import express from 'express'
import 'dotenv/config'  // dotenv file configuration
import jwt from 'jsonwebtoken'
import cookieParser from 'cookie-parser'

const PORT = process.env.PORT || 4000;
const app = express();
const secretKey = "secretKey";
const refreshSecretKey = "refreshSecretKey";

app.use(express.json());
app.use(cookieParser());

//! In-memory storage (in real apps, use DB/Redis)
let refreshTokensArr = [];

//! Generate Access Token
const generateAccessToken = (user) => {
    return jwt.sign({ user }, secretKey, { expiresIn: '300s' });
};

//! Generate Refresh Token
const generateRefreshToken = (user) => {
    const refreshToken = jwt.sign({ user }, refreshSecretKey, { expiresIn: '3d' });
    refreshTokensArr.push(refreshToken);
    return refreshToken;
};

//! Verify Token Middleware
function verifyToken(req, res, next) {
    //! Extracting token from headers.
    const bearerHeader = req.cookies.Cookie;
    if (!bearerHeader || !bearerHeader.startsWith('Bearer ')) {
        return res.json({ msg: "Invalid authorization header format" });
    }
    const bearer = bearerHeader.split(" ");
    if (bearer.length !== 2 || bearer[0] !== "Bearer") {
        return res.status(401).json({ msg: "Invalid authorization header format" });
    }
    const token = bearer[1];
    req.token = token;
    next();
}

//! Routes
app.get('/', (req, res) => {
    res.send('Get api Web token auth');
});

app.post('/logIn', (req, res) => {
    //! In real apps, validate user credentials here
    const user = {
        id: 2,
        name: "Mani101",
        email: "test@gmail.com"
    };
    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);

    //!Storing Refresh Token into cookies via cookie-parser
    res.cookie('refreshToken', refreshToken, {
        httpOnly: true, //! JS can't access it
        secure: false,  //! Set to true only if using HTTPS
        sameSite: 'Strict', //! Prevent CSRF
        maxAge: 3 * 24 * 60 * 60 * 1000 //! 3 days
    });
    res.json({ accessToken,refreshToken });
});

app.post('/profile', verifyToken, (req, res) => {
    //! Verifying token
    jwt.verify(req.token, secretKey, (error, authData) => {
        if (error) return res.status(401).json({ result: "Invalid Token" });
        res.json({ message: "Profile accessed", authData });
    });
});

app.post('/refresh-token', (req, res) => {
    const refreshToken = req.cookies.refreshToken;
    if (!refreshToken || !refreshTokensArr.includes(refreshToken)) {
        return res.status(403).json({ msg: "Refresh Token not valid" });
    }

    jwt.verify(refreshToken, refreshSecretKey, (error, userData) => {
        if (error) return res.status(403).json({ msg: "Refresh token expired or invalid" });

        const newAccessToken = generateAccessToken(userData.user);
        const newRefreshToken = generateRefreshToken(userData.user);

        //! Remove old refresh token and store new one
        refreshTokensArr = refreshTokensArr.filter(token => token !== refreshToken);
        refreshTokensArr.push(newRefreshToken);

        res.cookie('refreshToken', newRefreshToken, {
            httpOnly: true,
            secure: false, //! Set to true only if using HTTPS
            sameSite: 'Strict',
            maxAge: 3 * 24 * 60 * 60 * 1000
        });

        res.json({ accessToken: newAccessToken, refreshToken: newRefreshToken });
    });
});

app.post('/logOut', (req, res) => {
    const refreshToken = req.cookies.refreshToken;
    refreshTokensArr = refreshTokensArr.filter(token => token !== refreshToken);
    res.clearCookie('refreshToken', {
        httpOnly: true,
        secure: false, //! (true) if using HTTPS
        sameSite: 'Strict'
    });
    res.json({ message: "Logged out" });
});

app.listen(PORT, () => console.log(`http://localhost:${PORT}`));