/*
 ! [Important]: Everytime we just need to change the global variable value of access token.
 ? Everytime we use a refreshToken to regenerate a new accessToken.
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
    const accessToken = jwt.sign({ user }, secretKey, { expiresIn: '2m' });
    return accessToken;
};

//! Generate Refresh Token
const generateRefreshToken = (user) => {
    const refreshToken = jwt.sign({ user }, refreshSecretKey, { expiresIn: '3d' });
    refreshTokensArr.push(refreshToken);
    return refreshToken;
};

//! Verify Token Middleware
function verifyToken(req, res, next) {
    //! Using standard Authorization section -> [Type]Bearer Token
    const bearerHeader = req.headers['authorization'];//!fetching variable from Authorization.
    const token = bearerHeader?.split(' ')[1];

    if (!bearerHeader || !bearerHeader.startsWith('Bearer ') || !token) {
        return res.status(401).json({ msg: "Unauthorized: Invalid or missing token" });
    }

    req.token = token;
    next();
};

//! Routes
app.post('/logIn', (req, res) => {
    //! In real apps, validate user need a db connection
    const user = {
        id: 2,
        name: "Mani101",
        email: "test@gmail.com"
    };
    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);

    //! Using Cookies for refresh-token
    res.cookie('refreshToken', refreshToken, {
        httpOnly: true, //! JS can't access it
        secure: false,  //! Set to true only if using HTTPS
        sameSite: 'Strict', //! Prevent CSRF
        maxAge: 3 * 24 * 60 * 60 * 1000 //! 3 days
    });
    res.json({ accessToken, refreshToken, message: "Logged In User" });
});

app.post('/profile', verifyToken, (req, res) => {    
    jwt.verify(req.token, secretKey, (error, authData) => {                
        if (error) return res.status(401).json({ result: "Invalid Token",token:req.token });
        res.json({ message: "Profile accessed",token:req.token, authData });
    });
});

app.post('/refresh-token', (req, res) => {
    const refreshToken = req.cookies.refreshToken;
    
    if (!refreshToken) return res.status(403).json({ msg: "Refresh Token not valid" });

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