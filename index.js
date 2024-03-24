const express = require('express');
const app = express();
const port = 3000;

app.use(express.json());

const authRoutes = require('./routes/auth.routes');


app.use('/api/auth', authRoutes);

app.listen(port, () => {
    console.log(`Servidor escuchando en http://localhost:${port}`);
});