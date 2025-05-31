import express from 'express'
import 'dotenv/config'  //dotenv file configuration
import jwt from 'jsonwebtoken' 


const PORT = process.env.PORT || 4000;
const app = express();
const secretKey = "secretKey";

//routes
app.get('/', (req, res) => {
    res.send('Get api Web token auth');
});

app.post('/logIn',(req,res)=>{
    console.log(req.body,'reqq');
    
    const user = {
        id:2,
        name:"Mani101",
        email:"test@gmail.com"
    };
    jwt.sign({user},secretKey,{expiresIn:'300s'},(err,token)=>{
        if(err) res.status(500).json({msg:"Error in token generation"});
        res.json({token});
    });
});

app.post('/profile',verifyToken,(req,res)=>{
    //verifying token
    jwt.verify(req.token,secretKey,(err,authData)=>{
        if(err) return res.send({result:"Invalid Token"});
        res.json({message:"Profile accessed",authData});
    });
});

function verifyToken(req,res,next){
    //extracting token from headers.
    const bearerHeader = req.headers['jwt_token'];
    if (!bearerHeader) {
        return res.status(500).json({msg:"Header Token is missing"});
    };
    const bearer = bearerHeader.split(" ");
    const token = bearer[1];   //!["Bearer", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."]
    req.token = token;
    next();
};

app.listen(PORT,()=>console.log(`http://localhost:${PORT}`));