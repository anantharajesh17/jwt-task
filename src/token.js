const {sign} = require('jsonwebtoken')

const createAccessToken = userId =>{
  return sign({userId}.process.env.ACCESS_TOKEN_SECRET,{
    expiresIn:'4d',
    
  })
}

const createRefreshToken = userId =>{
  return sign({userId}.process.env.REFRESH_TOKEN_SECRET,{
    expiresIn:'6d',
    
  })
}
const sendAccessToken = (res, req, accesstoken) => {
  res.send({
    accesstoken,
    email:req.body.email,
})
}

const sendRefreshtoken = (res, refreshtoken)=>{
  res.cookie('refreshtoken',refreshtoken,{
    httpOnly: true,
    path: '/refresh_token',
  })
  }

module.exports = {
  createAccessToken,
  createRefreshToken,
  sendAccessToken,
  sendRefreshtoken
}