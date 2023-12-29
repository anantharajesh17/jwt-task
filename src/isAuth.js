const {verify} = require('jsonwebtoken')

const isAuth = req => {
   const authorization = req.header['authorization'];
   if(!authorization) throw new Error("you need to login");

   //bearer token
   const token = authorization.split(' ')[1];
   const {userId} = verify(token, process.env.ACCESS_TOKEN_SECRET)
   return userId
  }

  module.exports = {
    isAuth
  }