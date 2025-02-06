const { Pool } = require('pg'); 
const dotenv = require('dotenv');
const fs = require('fs');

dotenv.config();

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false, // Use true se você quiser validar o certificado
        ca: fs.readFileSync('ca.pem').toString()
      }
});

pool.on('connect', () => {
    console.log('Base de dados conectada com sucesso');
});

module.exports = {
    query : (text, params) => pool.query(text, params),
};