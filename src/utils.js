import { fileURLToPath } from 'url';
import { dirname } from 'path';
import bcrypt from 'bcrypt'
import passport from "passport";

// Para handlebars
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

export default __dirname;

// Para bcrypt

export const createHash = (password) => bcrypt.hashSync(password,bcrypt.genSaltSync(10));

export const isValidPassword = (user, password) => bcrypt.compareSync(password, user.password)

// Para jwt con cookies

export const cookieExtractor = (req) => {
    let token;
    if (req && req.cookies) {
        token = req.cookies['coderCookie']
    }
    return token;
}

// Para manejo de errores con passport

export const passportCall = (strategy)=> {
    return async (req, res, next) => {
        passport.authenticate(strategy, function(err, user, info){
            if (err) return next(err);
            if (!user) {
                return res.status(401).send({error: info.messages ? info.messages : info.toString()});
            }
             req.user = user;
            next();
        })(req,res,next)
    }
}

export const authorization = (role) => {
    return async(req, res, next)=> {
        if (!req.user) {
            return res.status(401).send({error: 'Unauthorized'});
        }
        if (req.user.role != role) {
            return res.status(403).send({error: 'No permissions'});
        }
        next();
    }
}