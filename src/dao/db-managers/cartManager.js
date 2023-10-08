import { cartModel } from "../models/cart.js";

class CartManager {

    constructor() {
    }

    getAll = async () => {

        const carts = await cartModel.find()
        return carts.map(cart => cart.toObject());
    }

    addCart = async (cart) => {

        try {
            const result = await cartModel.create(cart);
            return result
        } catch (error) {
            throw error
        }
    }

    getCartById = async (idCart) => {

        try {
            const cart = await cartModel.findById(idCart).lean();
            return cart
        } catch (error) {
            throw error
        }
    }

    addProductToCart = async (idCart, idProduct) => {
        try {
            const cart = await cartModel.findById(idCart);

            const existingProductIndex = cart.products.findIndex(e => e.product._id == idProduct)

            if (existingProductIndex >= 0) {
                cart.products[existingProductIndex].quantity += 1;
            } else {
                cart.products.push({
                    product: idProduct
                })
            }

            const result = await cartModel.findByIdAndUpdate(
                idCart,
                cart,
                { new: true }
            );
            return result;
        } catch (error) {
            throw error
        }
    }

    deleteProductToCart = async (idCart, idProduct) => {
        try {
            const result = await cartModel.findOneAndUpdate(
                { _id: idCart },
                { $pull: { products: { product: idProduct } } },
                { new: true }
            )
            return result;
        } catch (error) {
            throw error
        }
    }

    updateCartProducts = async (idCart, products) => {
        try {
            const result = await cartModel.findOneAndUpdate(
                { _id: idCart },
                { $push: { products: products } },
                { new: true }
            )
            return result;
        } catch (error) {
            throw error
        }
    }

    updateQuantityOfProducts = async (idCart, idProduct, newQuantity) => {
        try {
            const result = await cartModel.findOneAndUpdate(
                { _id: idCart, 'products.product': idProduct  },
                { $set: { 'products.$.quantity': newQuantity } },
                { new: true }
            )
            return result;
        } catch (error) {
            throw error
        }
    }

    deleteCartProducts= async (idCart) => {
        try {
            const result = await cartModel.findOneAndUpdate(
                { _id: idCart },
                { $set: { products: [] } },
                { new: true }
            )
            return result;
        } catch (error) {
            throw error
        }
    }

}

export default CartManager;