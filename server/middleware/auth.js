const { User } = require("../models/User")

let auth = (req, res, next) => {
    //인증 처리 하는 곳

    //1. client cookie에서 token 가져오기
    let token = req.cookies.x_auth;

    //2. token 복호화하고 user 찾기
    User.findByToken(token, (err, user) => {
        if(err) throw err;
        if(!user) return res.json({ isAuth: false, error: true })

        req.token = token;
        req.user = user;

        next();
    })
}

module.exports = { auth }