import React from 'react';
import ReactDOM from 'react-dom';
import {BrowserRouter, Route, Redirect,Switch} from 'react-router-dom';
import App from './App';
import Private from './pages/Private.jsx';
import Admin from './pages/Admin.jsx';
import Register from './pages/Register.jsx'
import Activate from './pages/Activate.jsx';
import Login from './pages/Login.jsx';
import Forget from './pages/Forget.jsx';
import ResetPassword from './pages/Reset.jsx'

import PrivateRoute from './routes/PrivateRoute';
import AdminRoute from './routes/AdminRoute';
import 'react-toastify/dist/ReactToastify.css';

ReactDOM.render(
    <BrowserRouter>
      <Switch>
        <Route path='/' exact render={props=><App {...props}/>} />
        <Route path='/register' exact render={props=><Register {...props}/>} />
        <Route path='/login' exact render={props=><Login {...props}/>} />
        <Route path='/users/password/forget' exact render={props=><Forget {...props}/>} />
        <Route path='/users/activate/:token' exact render={props=><Activate {...props}/>} />
        <Route path='/users/password/reset/:token' exact render={props=><ResetPassword {...props}/>} />
        <PrivateRoute path="/private" exact component={Private} />
        <AdminRoute path="/admin" exact component={Admin} />
        <Redirect to='/' />
      </Switch>
    </BrowserRouter>
  ,document.getElementById('root')
);

// If you want your app to work offline and load faster, you can change
// unregister() to register() below. Note this comes with some pitfalls.
// Learn more about service workers: https://bit.ly/CRA-PWA

