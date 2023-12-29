//require('dotenv/config');
const dotenv = require('dotenv').config();

const express = require('express');
// const cookieparser = require('cookie-Parser');
const cors = require('cors');
const {verify} = require('jsonwebtoken');
const {hash, compare} = require('bcrypt');
const port = process.env.port || 6000;
const {fakeDb} = require('./fakeDb');
const {isAuth} = require('./isAuth');

//1.register, 2.login 3.logout, 4.protected route, 5.get access refresh token
const {createAccessToken, createRefreshToken, sendAccessToken, sendRefreshtoken} = require('./token')
const server = express();

server.use(cookieparser());
server.use(
  cors({
    orgin:"http://localhost:8000",
    creadentials:true,
  })
);

server.use(express.json());
server.use(express.urlencoded({extended:true}));


//reg
server.post("/register", async (req,res)=>{
  const {email,password} = req.body;
  try{
    //check the user exits
    const user = fakeDb.find(user =>user.email === email);
    if(user) throw new Error('user already register in fake db')
    //if not user exits
    const hashedPassword = await hash(password, 10);
    //inset user in fakedb
    fakeDb.push({
      id:fakeDb.length,
      email,
      password:hashedPassword
    })
    res.send({message:"user created"});
    console.log(fakeDb);

  }catch(err){
   res.send({
    error:`${err.message}`
   })
  }
})

//login user
server.post("/login", async(req,res)=>{
  const{email,password} = req.body;

  try{
   //1.find user in database if not exist send err
   const user = fakeDb.find(user=>user.email === email)
   if(!user) throw new Error('user was not register kindly register 1st');
   //2.compare crypted password
   const valid = await compare(password, user.password);
   if(!valid) throw new Error('user password as not match')
   //3.if its correted refresh and accesstoken
   const accesstoken = createAccessToken(user.id)
   const refreshtoken = createRefreshToken(user.id)
   //4.put refresh token in data base
   user.refreshtoken = refreshtoken;
   console.log(fakeDb);
   //5.send token.refreshtoken as a cookie and access token as reguler response
   sendRefreshtoken(res, refreshtoken);
   sendAccessToken(res, req, accesstoken)
  }catch (err) {
     res.send({
      error:`${err.message}`,
      //console.log(err);
     })
  }
})
//logout user
server.post('/logout', (req,res)=>{
  res.clearCookie('refreshtoken',{path:'/refresh_token'});
  return res.send({
    message:'logout',
  })
});

//producted route
server.post('/protected', async(req,res)=>{
  try {
    const userId = isAuth(req);
    if(userId !==null){
      res.send({
        data:'this is protected data'
      })
    }
  } catch (error) {
    res.send({
      error:`${error.message}`
    })
  }
})

//new acces token with refresh token
server.post('/refresh_token', (req,res)=>{
  const token = req.cookie.refreshtoken;

  if(!token) return res.send({accesstoken:''})

  //now verify a token
 let paylode = null;
 try{
     paylode = verify(token, process.env.REFRESH_TOKEN_SECRET)
 }catch(err){
    return res.send({accesstoken:''})
 }
//token is vaild check if user exist 
const user = fakeDb.find(user => user.Id === paylode.userId);
if(!user) return res.send({accesstoken:''});
//user exist, check if refreshtoken exitst on user
if(user.refresh_token !== token){
  return res.send({accesstoken:''})
}
//token exits create new refresh and accesstoken
const accesstoken = createAccessToken(user.id);
const refreshtoken = createRefreshToken(user.id);
user.refreshtoken = refreshtoken;

//all good , send new refresh token and access token
sendRefreshtoken(res,refreshtoken);
return res.send({accesstoken});
})

server.listen(port,()=>{
  console.log(`server runing on port .....${port}`);
