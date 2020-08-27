const express = require('express');
const connectDB = require('./config/db');
require('dotenv').config({
  path: './config/config.env',
});

const app = express();

// * connect to db
connectDB();
app.use(express.json());
//* load all routes
const authRoute = require('./routes/auth.route');
const userRouter = require('./routes/user.route');

//* use routes
app.use('/api', authRoute);
app.use('/api', userRouter);

app.use((req, res, next) => {
  res.status(404).json({
    success: false,
    message: 'Page not found',
  });
});

const PORT = process.env.PORT;
app.listen(PORT, () => {
  console.log(`App listening on port ${PORT}`);
});
