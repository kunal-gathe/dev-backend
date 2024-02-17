import mongoose, { Schema } from 'mongoose'
import jwt from 'jsonwebtoken'
import bcrypt from 'bcrypt'

const userSchema = new Schema({
  userName: {
    type: String,
    required: true,
    unique: true,
    lowerCase: true,
    trim: true,
    index: true,
  },
  email: {
    type: String,
    required: true,
    unique: true,
    lowerCase: true,
  },
  fullName: {
    type: String,
    required: true,
    trim: true,
    index: true,
  },
  avatar: {
    type: String, // cloudinary url
    required: true,
  },
  coverImage: {
    type: String, 
  },
  watchHistory: [
    {
      type: Schema.Types.ObjectId,
      ref: 'Video',
    },
  ],

  password:{
    type: String,
    required: [true, 'Password is required'],

  },
  refreshToken:{
    type: String,
  }
},{timestamps:true})

//encrypt password
userSchema.pre('save', function (next){
        if(!this.isModified("password")) return next()
        this.password = bcrypt.hash(this.password,10)
        next()
})

// custom methods check password is same
userSchema.methods.isPasswordCorrect = async function (password){
 return await  bcrypt.compare(password, this.password)
}

// generate access token
userSchema.methods.generateAccessToken = function (){
   return jwt.sign(
        {
            _id: this.id,
            email: this.email,
            username: this.userName,
            fullName: this.fullName
        },

        process.env.ACCESS_TOKEN_SECRET,
        {
            expiresIn: process.env.ACCESS_TOKEN_EXPIRY
        }


    )
}
// generate Refresh token
userSchema.methods.generateRefreshToken = function (){
    return jwt.sign(
        {
            _id: this.id,
        },

        process.env.ACCESS_TOKEN_SECRET,
        {
            expiresIn: process.env.ACCESS_TOKEN_EXPIRY
        }


    )
}

export const User = mongoose.model('User', userSchema)
