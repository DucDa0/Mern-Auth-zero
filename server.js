const express=require('express');
const morgan=require('morgan');
const bodyParser=require('body-parser');
const cors=require('cors');
const connectDB=require('./config/db');
require('dotenv').config({
    path:'./config/config.env'
})

const app=express();

// * connect to db
connectDB();
app.use(bodyParser.json());
//* load all routes
const authRoute=require('./routes/auth.route');
const userRouter = require('./routes/user.route');
//* config for only dev
if(process.env.NODE_ENV==='development'){
    app.use(cors({
        origin: process.env.CLIENT_URL
    }));
    app.use(morgan('dev'));
    //* morgan give info about each request
    //* cors allow to deal with react for localhost at port 3000 without any problem
}




//* use routes
app.use('/api', authRoute);
app.use('/api', userRouter)


app.use((req,res,next)=>{
    res.status(404).json({
        success: false,
        message: 'Page not found'
    })
})

const PORT=process.env.PORT;
app.listen(PORT,()=>{
    console.log(`App listening on port ${PORT}`)
})