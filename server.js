import express from "express";
import path from 'path';
import mongoose from "mongoose";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken"; 
import bcrypt from "bcrypt";
import {config} from "dotenv";
const app = express();
// const users=[];

//Connecting to mongo database

// process.env.MONGO_URL

// const MONGO_URL = 'mongodb+srv://gurkamal01382:gurii@cluster0.yh41qhi.mongodb.net/?retryWrites=true&w=majority'
config({
    path: "./config.env",
})
mongoose.connect(process.env.MONGO_URL,{dbName:"backend"})
.then(()=> console.log("Database Connected"))
.catch((e)=>console.log(e));

//making a schema
const userSchema = new mongoose.Schema({
    name:String,
    email:String,
    password: String,
});

const User = mongoose.model("User",userSchema);  

// Middleware to parse URL-encoded form data
app.use(express.urlencoded({extended: true}));

app.use(express.static(path.join(path.resolve(),"public")));
app.use(cookieParser());

// app.get("/",(req,res) =>{
//     // res.send("Hi");
//     // res.sendStatus(500);
//     // const pathname = path.resolve();
//     // res.sendFile(path.join(pathname,"./index.html"));

//     // res.render("index.ejs", {name: "Chobbar"});

//     const token=req.cookies.token;
//     // console.log(req.cookies.token);
//     if(token)res.render("logout.ejs");
//     else res.render("login.ejs");
// })

const isAuthenticated = async (req,res,next) =>{
    const {token} = req.cookies;
    if(token){
        const decoded = jwt.verify(token, "thisisasecretkey");
        req.user = await User.findById(decoded._id);
        next();
    }
    else{
        res.redirect("/login");
    }
};

app.get("/", isAuthenticated,(req,res) =>{
    console.log(req.user);
    res.render("logout.ejs", {name : req.user.name});
});
app.get("/login", (req,res)=>{
    res.render("login.ejs");
})
app.get("/register", (req,res) => {
    res.render("register.ejs");
})

app.post("/login", async (req,res) =>{
    const {email,password} = req.body;
    const olduser = await User.findOne({email});
    if(!olduser){
        // alert("User doesnot exist.");
        return res.redirect("/register");
    }
    const isMatch =await bcrypt.compare(password,olduser.password);
    if(!isMatch){
        return res.render("login.ejs" , {email, message: "Incorrect Password"})
    }
    const token = jwt.sign({_id:olduser._id}, "thisisasecretkey")
    res.cookie("token",token,{
        httpOnly:true,
        expires: new Date(Date.now()+60*1000),
    });
    res.redirect("/");
})

app.post("/register",async (req,res)=>{
    const {name,email,password}= req.body; 

    const olduser=await User.findOne({email});
    if(olduser){
        // alert("user already exists.");
        return res.redirect("/login");
    }
    const hashedpass = await bcrypt.hash(password,10);
    const user = await User.create({
        name,
        email,
        password : hashedpass,
    });
    // console.log(req.body);

    const token = jwt.sign({_id:user._id}, "thisisasecretkey")
    res.cookie("token",token,{
        httpOnly:true,
        expires: new Date(Date.now()+60*1000),
    });
    res.redirect("/"); 
})

app.get("/logout",(req,res)=>{
    res.cookie("token",null,{
        httpOnly:true,
        expires: new Date(Date.now()),
    });
    res.redirect("/"); 
})



app.listen(3000,()=>{
    console.log("server is working");
})