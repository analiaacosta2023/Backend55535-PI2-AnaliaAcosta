import { productModel } from '../models/product.js'

class ProductManager {

    constructor() {
    }

    getAll = async (query) => {

        try {

            const limit = query.limit || 10
            const page = query.page || 1
            let categoryQuery = {};
            let stockQuery = {};
            const sortOptions = {};

            if (query.category) { categoryQuery = { category: query.category } }
            if (query.stock) { stockQuery = { $and: [{ stock: { $exists: true } }, { stock: { $ne: 0 } }]}}
            if (query.sort === 'asc') {
                sortOptions.price = 1;
            } else if (query.sort === 'desc') {
                sortOptions.price = -1;
            }

            const result = await productModel.paginate( { ...categoryQuery, ...stockQuery }, { limit, page, sort: sortOptions });
            result.docs = result.docs.map((doc) => doc.toObject());
            return result;

        } catch (error) {
            throw error
        }
    }

    addProduct = async (product) => {

        try {
            const result = await productModel.create(product);
            return result
        } catch (error) {
            throw error
        }
    }

    getProductById = async (idProducto) => {

        try {
            const result = await productModel.findById(idProducto).lean();
            return result
        } catch (error) {
            throw error
        }
    }

    updateProduct = async (idProducto, propertiesToUpdate) => {

        try {
            const result = await productModel.findByIdAndUpdate(
                idProducto,
                propertiesToUpdate,
                { new: true }
            );
            return result;
        } catch (error) {
            throw error
        }
    }


    deleteProduct = async (idProducto) => {
        try {
            const result = await productModel.findByIdAndDelete(idProducto);
            return result;
        } catch (error) {
            throw error
        }
    }

}

export default ProductManager;

