import express from 'express';
import 'dotenv/config'  //dotenv file configuration

const PORT = process.env.PORT || 4000;
const app = express();

app.listen(PORT,()=>console.log(`App is running on port ${PORT}`));