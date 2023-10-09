import { Router } from "express";
import { userModel } from "../dao/models/user.js";
import { createHash } from "../utils.js";
import passport from "passport";
import jwt from 'jsonwebtoken';
import { authorization, passportCall } from "../utils.js";

const router = Router();

router.post('/login', passport.authenticate('login', { session: false, failureRedirect: '/api/sessions/failLogin' }), async (req, res) => {

    const serializedUser = {
        id: req.user._id,
        first_name: req.user.first_name,
        last_name: req.user.last_name,
        email: req.user.email,
        cart: req.user.cart,
        role: req.user.role
    }
    const token = jwt.sign(serializedUser, 'coderSecret', { expiresIn: '1h' })
    res.cookie('coderCookie', token, { maxAge: 3600000 }).send({ status: "success", payload: serializedUser });
})

router.get('/github', passport.authenticate('github', { scope: ['user:email'] }), async (req, res) => { })

router.get('/githubCallback', passport.authenticate('github', { session: false, failureRedirect: '/failLogin' }), async (req, res) => {

    const serializedUser = {
        id: req.user._id,
        first_name: req.user.first_name,
        last_name: req.user.last_name,
        email: req.user.email,
        cart: req.user.cart,
        role: req.user.role
    }

    const token = jwt.sign(serializedUser, 'coderSecret', { expiresIn: '1h' })
    res.cookie('coderCookie', token, { maxAge: 3600000 })
    res.redirect('/products')
})

router.get('/failLogin', (req, res) => {
    res.status(401).send({ status: "error", error: "Failed login" })
})

router.post('/register', passport.authenticate('register', { session: false, failureRedirect: '/api/sessions/failRegister' }), async (req, res) => {
    res.send({ status: "success", message: "Usuario registrado" })
})

router.get('/failRegister', async (req, res) => {
    console.log("Fallo la estrategia");
    res.status(400).send({ status: "error", error: 'Failed register' });

})


router.get('/logout', (req, res) => {
    try {
        res.clearCookie('coderCookie');
        res.redirect('/login');
    } catch (error) {
        return res.status(500).send({ status: 'error', error: 'Internal Server Error' });
    }

});

router.put('/restartPassword', async (req, res) => {
    const { email, password } = req.body;
    console.log('hola')
    if (!email || !password) {
        return res.status(400).send({ status: "error", error: "Datos incompletos" });
    }
    const user = await userModel.findOne({ email });
    if (!user) {
        return res.status(404).send({ status: "error", error: "No existe el usuario" });
    }
    const passwordHash = createHash(password);
    await userModel.updateOne({ email }, { $set: { password: passwordHash } })
    res.send({ status: "success" })

})

router.get('/current', passportCall('jwt'), authorization('usuario'), (req, res) => {
    res.send({ status: "success", payload: req.user })
})

export default router;