const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const connection = require('../configBD/dataBase');

const SECRET_KEY = 'clavesegura';

exports.register = (req, res) => {
    const {username, password, role} = req.body;

    connection.query('SELECT * FROM users WHERE username = ?', [username], (err, results) => {
        if (err) throw err;
        if (results.length > 0){
            return res.status(400).json({message: 'El nombre de usuario ya esta en uso'});
        }

        const salt = bcrypt.genSaltSync(10);
        const hashedPasword = bcrypt.hashSync(password, salt);

        connection.query('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', [username, hashedPasword, role], (err, result) =>{
        if (err) throw err;
        res.status(201).json({message: 'Usuario registrado correctamente'});  
    })
    });
};

exports.login = (req, res) => {
    const {username, password} = req.body;

    connection.query('SELECT * FROM users WHERE username = ?', [username], (err, results) =>{
        if (err) throw err;
        if (results.length === 0) {
            return res.status(401).json({message: 'Credenciales incalidas'});
        }
        
        const user = results[0];

        const isPasswordValid = bcrypt.compareSync(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json()
        }

        const token = jwt.sign({userId: user.id, role: user.role}, SECRET_KEY, { expiresIn: '1h'});

        res.json({ token});
    });
};

exports.profile = (req, res) => {

    const token = req.headers.authorization?.split(' ')[1];
    if (!token){
        return res.status(401).json({ message: 'No está autorizado'})
    }

    try {
        const decoded = jwt.verify(token, SECRET_KEY);
        const { userId, sole} = decoded;

        connection.query('SELECT username, role FROM users WHERE id = ?', [userId], (err, results) => {
            if (err) throw err;
            if (results.length === 0){
                return res.status(404).json({ message: 'Usuario no encontrado' });
            }

            const { username, role } = results[0];
            res.json({ username, role });
        });
    }catch (err) {
        res.status(401).json({ message: 'Token invalido' });
    }
};
