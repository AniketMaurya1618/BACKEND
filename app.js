const dotenv = require('dotenv');
dotenv.config();
const express=require('express');
const cors = require('cors');
const app = express();
const connectToDb = require('./db/db');
const userRoutes = require('../BACKEND/Routes/user.routes');

connectToDb(); 

// for domains url
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({extended: true}));

app.get('/', (req, res)=>{
    res.send('hello world');
});
app.use('/users', userRoutes)

module.exports =app;