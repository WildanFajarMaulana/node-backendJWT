import {Sequelize} from "sequelize"

const db = new Sequelize('authJwtNodejs','root','',{
	host:"localhost",
	dialect:"mysql"
})

export default db;