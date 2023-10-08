import { Router, query } from 'express';
import ProductManager from '../dao/db-managers/productManager.js'
import CartManager from '../dao/db-managers/cartManager.js'
import { authorization, passportCall } from "../utils.js";

const productManager = new ProductManager()
const cartManager = new CartManager()

const router = Router();

const publicAccess = (req, res, next) => {
    if (req.user) return res.redirect('/products');
    next();
}

const privateAccess = (req, res, next) => {
    if (!req.user) {
        return res.redirect('/login');
    }
    next();
}

router.get('/', async (req, res) => {

    const { docs } = await productManager.getAll({});

    res.render('home', { style: "index.css", docs })
})

router.get('/realtimeproducts', async (req, res) => {

    res.render('realTimeProducts', { style: "index.css" })
})

router.get('/chat', passportCall('jwt'), privateAccess, async (req, res) => {

    res.render('chat', { style: "index.css", user: req.user })
})

router.get('/products', passportCall('jwt'), privateAccess, async (req, res) => {

    const query = req.query

    const { docs, hasPrevPage, hasNextPage, nextPage, prevPage, totalPages, page } = await productManager.getAll(query);

    res.render('products', { style: "index.css", user: req.user, docs, hasPrevPage, hasNextPage, nextPage, prevPage, totalPages, page })
})

router.get('/products/:pid', passportCall('jwt'), privateAccess, async (req, res) => {

    const pid = req.params.pid

    try {
        const product = await productManager.getProductById(pid);

        res.render('sproduct', { style: "index.css", user: req.user, product })
    } catch (error) {
        console.log(error)
    }


})

router.get('/carts/:cid', passportCall('jwt'), privateAccess, async (req, res) => {

    try {
        const cid = req.params.cid

        const cart = await cartManager.getCartById(cid)

        res.render('cart', { cart })

    } catch (error) {
        res.status(404).send(`Cart not found: ${error.message}`);
    }

})

router.get('/login', publicAccess, (req, res) => {
    res.render('login', { style: "index.css" })
})

router.get('/register', publicAccess, (req, res) => {
    res.render('register', { style: "index.css" })
})

router.get('/resetpassword', publicAccess, (req, res) => {
    res.render('resetPassword', { style: "index.css" })
})

export default router;