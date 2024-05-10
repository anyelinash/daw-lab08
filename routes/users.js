const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const { body, validationResult } = require('express-validator');
const Joi = require('joi');

const router = express.Router();

// Definir esquema de validación con Joi
const userSchema = Joi.object({
  name: Joi.string().trim().required(),
  email: Joi.string().trim().email({ minDomainSegments: 2, tlds: { allow: ['com'] } }).required(),
  password: Joi.string().trim().min(6).regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{6,}$/).required()
    .messages({
      'string.pattern.base': 'La contraseña debe contener al menos una mayúscula, un número y un carácter especial.'
    })
});

// Modelo de usuario en mongoose
const User = mongoose.model('User', new mongoose.Schema({
  name: String,
  email: String,
  password: String
}));

const saltRounds = 10; // Número de saltos para generar el hash

// Middleware para validar los datos del formulario de usuario
const validateUserData = (req, res, next) => {
  const { error } = userSchema.validate(req.body);
  if (error) {
    return res.status(400).json({ error: error.details[0].message });
  }
  next();
};

router.get('/', async (req, res) => {
  const users = await User.find();
  res.render('index', { users });
});

// Ruta para guardar un nuevo usuario
router.post('/', validateUserData, async (req, res) => {
  try {
    // Encriptar la contraseña antes de guardarla en la base de datos
    const hashedPassword = await bcrypt.hash(req.body.password, saltRounds);
    const newUser = new User({
      name: req.body.name,
      email: req.body.email,
      password: hashedPassword // Guardar la contraseña encriptada
    });
    await newUser.save();
    res.redirect('/users');
  } catch (error) {
    console.error(error);
    res.status(500).send('Error al guardar el usuario');
  }
});

// Ruta para editar un usuario
router.get('/edit/:id', async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    res.render('partials/edit', { user });
  } catch (error) {
    console.error(error);
    res.status(500).send('Error al obtener el usuario');
  }
});

// Ruta para actualizar un usuario
router.post('/update/:id', validateUserData, async (req, res) => {
  try {
    const user = await User.findById(req.params.id);

    // Verificar si se proporcionó una nueva contraseña en el formulario
    if (req.body.password !== '') {
      // Si se proporciona una nueva contraseña, encriptarla antes de guardarla
      req.body.password = await bcrypt.hash(req.body.password, saltRounds);
    } else {
      // Si no se proporciona una nueva contraseña, mantener la 
      // contraseña existente en la base de datos
      req.body.password = user.password;
    }

    await User.findByIdAndUpdate(req.params.id, req.body);
    res.redirect('/users');
  } catch (error) {
    console.error(error);
    res.status(500).send('Error al actualizar el usuario');
  }
});

// Ruta para eliminar un usuario
router.get('/delete/:id', async (req, res) => {
  try {
    await User.findByIdAndDelete(req.params.id);
    res.redirect('/users');
  } catch (error) {
    console.error(error);
    res.status(500).send('Error al eliminar el usuario');
  }
});

module.exports = router;
