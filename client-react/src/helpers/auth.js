import cookie from 'js-cookie'

//* set in cookie
export const setCookie=(key, value)=>{
    if(window !== 'undefined'){
        cookie.set(key,value,{
            expires: 1 //* 1 day
        })
    }
}

// * remove form cookie
export const removeCookie=key=>{
    if(window!=='undefined'){
        cookie.remove(key,{
            expires: 1
        })
    }
}

// *get from cookie
export const getCookie=key=>{
    if(window!=='undefined'){
        return cookie.get(key);
    }
}
// * set in localstorage
export const setLocalStorage=(key,value)=>{
    if(window!=='undefined'){
        localStorage.setItem(key,JSON.stringify(value));
    }
}
// * remove from localstorage
export const removeLocalStorage=(key)=>{
    if(window!=='undefined'){
        localStorage.removeItem(key);
    }
}

// * auth user after login
export const authenticate=(response,next)=>{
    setCookie('token', response.data.token);
    setLocalStorage('user',response.data.user);
    next();
}

// * signout
export const signout = next => {
    removeCookie('token');
    removeLocalStorage('user');
    next();
};

//* get user info from localstorage
export const isAuth=()=>{
    if(window!=='undefined'){
        const cookieChecked=getCookie('token');
        if(cookieChecked){
            if(localStorage.getItem('user')){
                return JSON.parse(localStorage.getItem('user'));
            }else{
                return false;
            }
        }
    }
}

//* update user data in localstrage
export const updateUser=(response,next)=>{
    if(typeof window!=='undefined'){
        let auth=JSON.parse(localStorage.getItem('user'));
        auth=response.data;
        localStorage.setItem('user',JSON.stringify(auth));
    }
    next();
}


