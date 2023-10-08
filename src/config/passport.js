import passport from "passport";
import local from "passport-local"
import gitHubStrategy from "passport-github2"
import jwt from 'passport-jwt';
import { userModel } from "../dao/models/user.js";
import { cookieExtractor, createHash, isValidPassword } from '../utils.js'
import CartManager from '../dao/db-managers/cartManager.js'

const cartManager = new CartManager()

const admin = {
    first_name: 'Admin',
    last_name: 'Coder',
    email: 'adminCoder@coder.com',
    password: 'adminCod3r123',
    role: 'admin'
}

const LocalStrategy = local.Strategy;
const GitHubStrategy = gitHubStrategy.Strategy;
const JWTStrategy = jwt.Strategy;
const ExtractJWT = jwt.ExtractJwt;


export const initializePassport = () => {
    passport.use('register', new LocalStrategy({ passReqToCallback: true, usernameField: 'email', session: false }, async (req, username, password, done) => {
        const { first_name, last_name, email, age } = req.body;
        try {

            if (email === admin.email) {
                return done(null, false, {message: 'Usuario ya existe'})
            }

            const exists = await userModel.findOne({ email });
            if (exists) {
                return done(null, false, {message: 'Usuario ya existe'})
            };
            const newUser = {
                first_name,
                last_name,
                email,
                age,
                cart:  await cartManager.addCart({}),
                password: createHash(password)
            };
            let result = await userModel.create(newUser);
            return done(null, result)
        } catch (error) {
            return done('Error al crear el usuario:' + error)
        }
    }));

    passport.use('login', new LocalStrategy({ usernameField: 'email', session: false }, async (username, password, done) => {
        try {
            let user
            if (username === admin.email && password === admin.password) {
                user = admin
            } else {
                user = await userModel.findOne({ email: username });
            }

            if (!user) {
                return done(null,false, {message: "Usuario no encontrado"})
            }
            if (!isValidPassword(user, password)) {
                return done(null, false, {message: "Contraseña incorrecta"})
            }
            return done(null, user);
        } catch (error) {
            return done(error)
        }
    }));

    passport.use('github', new GitHubStrategy({
        clientID: "Iv1.4bc3b8e167b094fc",
        clientSecret: "770c4d3155d8b1002800deacfb48ba687301865e",
        callBackURL: "http://localhost:8080/api/sessions/githubCallback",
        scope: ['user:email']
    }, async (accessToken, refreshToken, profile, done) => {
        try {

            const emailResponse = await fetch('https://api.github.com/user/emails', {
                method: 'GET',
                headers: {
                    'Authorization': `token ${accessToken}`,
                    'User-Agent': 'TiendaDeRemeras'
                }
            });
    
            if (emailResponse) {
                const emails = await emailResponse.json();
                const primaryEmail = emails.find(email => email.primary);
                
                if (primaryEmail) {
                    profile.email = primaryEmail.email;
                }
            }

            console.log(profile);
            let user = await userModel.findOne({ userName: profile._json.login})
            if (!user) {
                const cart =   await cartManager.addCart({})
                let newUser = { first_name: profile._json.name, last_name: '', age: null, cart, email: profile.email, userName: profile._json.login, password: '' }
                let result = await userModel.create(newUser);
                return done(null, result);
            }
            done(null, user)
        } catch (error) {
            return done(error)
        }
    }));

    passport.serializeUser((user, done) => {
        done(null, user._id)
    })

    passport.deserializeUser(async (id, done) => {
        let user = await userModel.findById(id);
        done(null, user);
    })

    passport.use('jwt', new JWTStrategy({
        jwtFromRequest: ExtractJWT.fromExtractors([cookieExtractor]),
        secretOrKey: 'coderSecret',
    }, async(jwt_payload, done)=> {
        try {
            return done(null, jwt_payload)
        } catch (error) {
            return done(error)
        }
    }))
   
}

