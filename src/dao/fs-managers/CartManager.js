import fs from 'fs'

class CartManager {

    constructor() {
        this.path = 'carrito.json';
    }

    getCarts = async () => {
        if (fs.existsSync(this.path)) {
            const data = await fs.promises.readFile(this.path, 'utf-8');
            const carritos = JSON.parse(data);
            return carritos;
        } else {
            return [];
        }
    }

    addCart = async () => {

        const carritos = await this.getCarts();

        const cart = {
            products: []
        }

        if (carritos.length === 0) {
            cart.id = 1;
        } else {
            cart.id = carritos[carritos.length - 1].id + 1;
        }

        carritos.push(cart);

        await fs.promises.writeFile(this.path, JSON.stringify(carritos))

        return cart

    }

    getCartById = async (idCart) => {

        const carritos = await this.getCarts();

        const cartIndex = carritos.findIndex(cart => cart.id === idCart);

        if (cartIndex >= 0) {
            return carritos[cartIndex];
        } else {
            throw new Error(`Carrito con id ${idCart} no existe`);
        }
    }

    addProductTocart = async (idCart, idProduct) => {

        const carritos = await this.getCarts();
        const cartIndex = carritos.findIndex(cart => cart.id === idCart);

        if (cartIndex >= 0) {

            const existingProductIndex = carritos[cartIndex].products.findIndex(product => product.productId === idProduct);
            if (existingProductIndex >= 0) {
                carritos[cartIndex].products[existingProductIndex].quantity += 1;
            } else {
                carritos[cartIndex].products.push({ productId: idProduct, quantity: 1 })
            }
            await fs.promises.writeFile(this.path, JSON.stringify(carritos))
            return carritos[cartIndex];
        } else {
            throw new Error(`Carrito con id ${idCart} no existe`);
        }
    }

}

export default CartManager;






