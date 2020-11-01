const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const saltRounds = 10
const jwt = require('jsonwebtoken')

const userSchema = mongoose.Schema({
    name: {
        type: String,
        maxlength: 50
    },
    email: {
        type: String,
        //스페이스 제거
        trim: true,
        //중복 안되게
        unique: 1
    },
    password: {
        type: String,
        minlength: 5
    },
    lastname: {
        type: String,
        maxlength: 50
    },
    role: {
        //0은 일반인, 1은 관리자
        type: Number,
        default: 0
    },
    image: String,
    token: {
        type: String
    },
    //토큰 유효기간
    tokenExp: {
        type: Number
    }
})

userSchema.pre('save', function( next ) {
    let user = this;

    if(user.isModified('password')) {
        //비밀번호 암호화
        bcrypt.genSalt(saltRounds, function(err, salt) {
            if(err) return next(err)

            bcrypt.hash(user.password, salt, function(err, hash/*암호화 된 비밀번호*/) {
                if(err) return next(err)

                user.password = hash

                next()
            })
        })
    } else {
        next()
    }
})

userSchema.methods.comparePassword = function(plainPassword, cb) {
    //plainPassword와 암호화된 password 비교
    //plainPassword를 암호화 해서 db의 암호화된 password랑 비교

    bcrypt.compare(plainPassword, this.password, function(err, isMatch) {
        if(err) return cb(err)

        cb(null, isMatch)
    })
} 

userSchema.methods.generateToken = function(cb) {
    let user = this;

    //jsonwebtoken 이용해 token을 생성
    let token = jwt.sign(user._id.toHexString(), 'secretToken')

    user.token = token
    user.save(function(err, user) {
        if(err) return cb(err)

        cb(null, user)
    })
}

userSchema.statics.findByToken = function(token, cb) {
    let user = this;

    //token decode
    jwt.verify(token, 'secretToken', function(err, decoded) {
        //user id 이용해서 유저를 찾은 다음
        //클라이언트에서 가져온 token과 DB에 보관된 token이 일치하는지 확인
        user.findOne({ "_id": decoded, "token": token }, function(err, user) {
            if(err) return cb(err);

            cb(null, user);
        })
    })
}

const User = mongoose.model('User', userSchema)

module.exports = { User }