import Users from "../models/UserModel.js"
import bcrypt from "bcrypt"
import jwt from "jsonwebtoken"
export const getUsers = async (req,res) =>{
	try{
		const users = await Users.findAll({
			attributes:['id','name','email']
		})
		res.status(200).json(users)
	}catch(e){
		console.log(e)
	}
}

export const Register = async (req,res) =>{
	const {name,email,password,confirmPassword} = req.body
	if(password != confirmPassword) return res.status(400).json({msg:"Password dan confirm tidak cocok"})

	const salt = await bcrypt.genSalt()
	const hashPassword = await bcrypt.hash(password,salt)
	try{
		const users = await Users.create({
			name:name,
			email:email,
			password:hashPassword
		})
		res.status(200).json({msg:"register berhasil",user:users})
	}catch(e){
		console.log(e)
	}
}

export const Login = async(req,res)=>{
	try{
		const user = await Users.findAll({
			where:{
				email:req.body.email
			}
		})
		const match = await bcrypt.compare(req.body.password,user[0].password)
		if(!match) return res.status(400).json({msg:"wrong password"})
		const userId = user[0].id
		const userName = user[0].name
		const userEmail = user[0].email

		const accessToken = jwt.sign({userId,userEmail,userName},process.env.ACCESS_TOKEN_SECRET,{
			expiresIn:'20s'
		});

		const refreshToken = jwt.sign({userId,userEmail,userName},process.env.REFRESH_TOKEN_SECRET,{
			expiresIn:'1d'
		});

		await Users.update({refresh_token:refreshToken},{
			where:{
				id:userId
			}
		});
		
		res.cookie('refreshToken',refreshToken,{
			httpOnly:true,
			maxAge:24*60*60*1000
		});
		res.json({accessToken});
	}catch(e){
		req.status(404).json({msg:"email tidak ditemukan"})
		console.log(e)
		
	}
}

export const Logout = async(req,res) =>{
	const refreshToken = req.cookies.refreshToken
    if(!refreshToken) return res.sendStatus(401)

    const user = await Users.findAll({
        where:{
            refresh_token:refreshToken
        }
	})
	if(!user[0]) return res.sendStatus(204)
	const userId = user[0].id
	await Users.update({
		refresh_token:null
	},{
		where:{
			id:userId
		}
	})
	res.clearCookie('refreshToken')
	return res.status(200);
}