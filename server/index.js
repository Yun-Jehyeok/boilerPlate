const express = require('express')
const app = express()
const port = 5000
const bodyParser = require('body-parser')
const cookieParser = require('cookie-parser')
const { User } = require('./models/User')
const { auth } = require('./middleware/auth')

const config = require('./config/key');

app.use(bodyParser.urlencoded({ extended: true }))
app.use(bodyParser.json())
app.use(cookieParser())

const mongoose = require('mongoose')
const { json } = require('body-parser')

mongoose.connect(config.mongoURI, {
    useNewUrlParser: true, useUnifiedTopology: true, useCreateIndex: true, useFindAndModify: false
}).then(() => console.log('MongoDB Connected..'))
    .catch(err => console.log(err))


//Home router
app.get('/', (req, res) => res.send('Hello world!'))


//join router
app.post('/api/users/register', (req, res) => {
    //1. 회원가입시 필요한 정보 client에서 받아오기
    //2. 데이터베이스에 데이터 저장

    const user = new User(req.body)

    user.save((err, userInfo) => {
        if(err) return res.json({ success: false, err })

        //status(200)은 성공의 의미
        return res.status(200).json({ 
            success: true
        })
    })
})


//login router
app.post('/api/users/login', (req, res) => {
    //요청된 이메일이 db에 있는지 찾기
    User.findOne({ email: req.body.email }, (err, user) => {
        if(!user) {
            return res.json({
                loginSuccess: false,
                message: "제공된 이메일에 해당하는 유저가 없습니다."
            })
        }

        //요청된 이메일이 db에 있다면 
        //비밀번호가 맞는지 확인
        user.comparePassword( req.body.password, (err, isMatch) => {
            if(!isMatch) return res.json({ 
                loginSuccess: false,
                message: "비밀번호가 틀렸습니다."
            })

            //비밀번호까지 맞다면
            //유저를 위한 토큰 생성
            user.generateToken((err, user) => {
                if(err) return res.status(400).send(err)

                //토큰을 쿠키에 저장한다.
                res.cookie("x_auth", user.token)
                .status(200)
                .json({ 
                    loginSuccess: true,
                    userId: user._id
                })
            })
        })
    })
})


app.get('/api/users/auth', auth, (req, res) => {
    //여기까지 미들웨어를 통과해 왔다는 얘기는 auth = true 라는 뜻
    
    res.status(200).json({
        //client 에 user 정보 제공

        _id: req.user._id,
        isAdmin: req.user.role === 0 ? false : true,
        isAuth: true,
        email: req.user.email,
        name: req.user.name,
        lastname: req.user.lastname,
        role: req.user.role,
        image: req.user.image
    })
})

//logout router
app.get('/api/users/logout', auth, (req, res) => {
    User.findOneAndUpdate({ _id: req.user._id }, { token: "" }, (err, user) => {
        if(err) return res.json({ success: false, err });

        return res.status(200).send({
            success: true
        })
    })
})

app.listen(port, () => console.log(`Example app listening on port ${port}!`))