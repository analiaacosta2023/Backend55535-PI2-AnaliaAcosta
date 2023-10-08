import { Router } from 'express';
import CartManager from '../dao/db-managers/cartManager.js'

const cartManager = new CartManager()

const router = Router();


router.post('/', async (req, res) => {

    try {
        const result = await cartManager.addCart({});
        res.send({ status: 'success', payload: result })
    } catch (error) {
        res.status(500).send({ status: 'error', message: error.message })
    }
})

router.get('/:cid', async (req, res) => {

    const cid = req.params.cid;

    try {
        const cart = await cartManager.getCartById(cid);
        res.send({ status: "success", payload: cart });
    } catch (error) {
        res.status(404).send({ status: 'error', message: error.message })
    }
})

router.post('/:cid/product/:pid', async (req, res) => {
    const cid = req.params.cid;
    const pid = req.params.pid;

    try {
        const cart = await cartManager.addProductToCart(cid, pid);
        res.send({ status: 'success', payload: cart });

    } catch (error) {
        res.status(500).send({ status: 'error', message: error.message })
    }
})

router.delete('/:cid/product/:pid', async (req, res) => {
    const cid = req.params.cid;
    const pid = req.params.pid;

    try {
        const cart = await cartManager.deleteProductToCart(cid, pid);
        res.send({ status: 'success', payload: cart });

    } catch (error) {
        res.status(500).send({ status: 'error', message: error.message })
    }
})

router.put('/:cid', async (req, res) => {
    const cid = req.params.cid;
    const products = req.body;

    try {
        const cart = await cartManager.updateCartProducts(cid, products);
        res.send({ status: 'success', payload: cart });

    } catch (error) {
        res.status(500).send({ status: 'error', message: error.message })
    }
})

router.put('/:cid/product/:pid', async (req, res) => {
    const cid = req.params.cid;
    const pid = req.params.pid;
    const newQuantity = req.body.quantity;

    try {
        const cart = await cartManager.updateQuantityOfProducts(cid, pid, newQuantity);
        res.send({ status: 'success', payload: cart });

    } catch (error) {
        res.status(500).send({ status: 'error', message: error.message })
    }
})

router.delete('/:cid', async (req, res) => {
    const cid = req.params.cid;

    try {
        const cart = await cartManager.deleteCartProducts(cid);
        res.send({ status: 'success', payload: cart });

    } catch (error) {
        res.status(500).send({ status: 'error', message: error.message })
    }
})


export default router;

