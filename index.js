const express=require("express");
const app=express();
app.use(express.json());

require("dotenv").config();

const cors=require("cors");
app.use(cors());

const bcrypt=require("bcrypt");

const mongodb=require("mongodb");
const mongoClient=mongodb.MongoClient;
const objectId=mongodb.ObjectId;

const JWT=require("jsonwebtoken");
const JWT_SECRET= process.env.JWT_SECRET_KEY;


const nodemailer=require("nodemailer");


var transporter = nodemailer.createTransport({
    service: 'gmail',
     port: 587,
  secure: false,
    auth: {
      user:"suryatest3@gmail.com",
      pass:process.env.pwd
    }
  });
  

const db_url=process.env.DB_URL || " mongodb://127.0.0.1:27017/";
const port= process.env.PORT || 4000;  


app.get("/all",async(req, res)=>{
    const client= await mongoClient.connect(db_url);
    const db= client.db("inventory")
    const data =await db.collection("user").find().toArray();
    res.status(200).json(data)
    client.close();
})



/** register*/


app.post("/register", async (req,res)=>{
    // connecting iwth mongo
    const client= await mongoClient.connect(db_url)
    if(client){
        try{
            // user info
            const info={
                email:req.body.email,
                password:req.body.password,
                isActivated:1
            }

            const db=client.db("inventory");
            const found=await db.collection("user").findOne({email:req.body.email});
           // checking user
            if(found){
                res.status(400).json({message:'user already exist'})
            }else{
                // hashing password
                let salt =await bcrypt.genSalt(10);
                let hash= await bcrypt.hash(req.body.password,salt);
                info.password=hash;
                let insertinto = await db.collection("user").insertOne(info);
               
               // creating token and nodemailer
                if(insertinto){
                    let token = await JWT.sign(info.email,JWT_SECRET);
                    var mailOptions = {
                        from: 'suryatest3@gmail.com',
                        to:req.body.email,
                        subject: 'Hai!!!',
                        text: "click below link to authenticate",
                        html:"<a>"+token+"</a>"
                      };

                      transporter.sendMail(mailOptions, function(error, info){
                        if (error) {
                          console.log(error);
                        } else {
                          console.log('Email sent: ' + info.response);
                        }});

                        res.status(200).json({message:"user created and see link"})
                }            
            }

        }catch(e){
            console.log(e)
            client.close();
        }

    }else{
        res.status(500).json({message:"internal srver error"})
    }
})

// activate user
app.get("/activate_user:token",async(req, res)=>{
    const client = await mongoClient.connect(db_url);

    if(client){
        const db= client.db("inventory");
        JWT.verify(req.param.token,JWT_SECRET,async(err,decode)=>{
            if(decode!==undefined){
                let activate= await db.collection("user").findOneAndUpdate({email:decode.email},{$set:{activate:1}});

                if(activate){
                  res.status(200).json({message:"user activated successfuly"})
                }
            }else{
                res.status(401).json({message:"invalid token"})
            }
        })

    }else{
        res.sendStatus(500).json({message:"internal server eoor"})
    }
});


// login

app.post("/login", async(req,res)=>{

    const client = await mongoClient.connect(db_url);

    if(client){
        try{
            const info={
                email:req.body.email,
                password:req.body.password
            }
            const db=client.db("inventory");
            const data= await db.collection("user").findOne({email:req.body.email})
            
            if(data.isActivated){

                const token= await JWT.sign(info.email,JWT_SECRET);
                res.status(200).json({message:"logged in success",token})

            }else{
                res.status(400).json({message:"user not activated"})
            }

        }catch(e){
            console.log(e)
        }
        


    }else{
        res.status(500).json({message:"internal server error"})
    }
})


app.get("/user", async(req,res)=>{

    const client = await mongoClient.connect(db_url);

    if(client){
        try{
            let access_token=req.headers.authorization;

            let verifyToken= await JWT.verify(access_token,JWT_SECRET);
            console.log(verifyToken);

            if(verifyToken){
                const db=client.db("inventory");
                const data= await db.collection("user").find().toArray();
                res.status(200).json(data);
                client.close();
            }else{
                res.status(401).json({message:"invalid token"}) 
            }
        }catch(e){
            console.log(e);
            client.close();
        }


    }else{
        res.status(500).json({message:"internal server error"})
    }

})




app.listen(port,()=>console.log(`app runs with ${port}`))
