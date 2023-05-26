import { Router } from 'express';
import { body, oneOf, validationResult } from 'express-validator';
import { handleInputErrors } from './modules/middleware';
import { createProduct, deleteProduct, getProduct, getProducts, updateProduct } from './handlers/product';

const router = Router();

// Products
router.get('/product', getProducts)
router.get('/product/:id', getProduct)
router.put('/product/:id', 
    body('name').isString(),
    handleInputErrors,
    updateProduct    
)
router.post('/product', 
    body('name').isString(),
    handleInputErrors,
    createProduct
)
router.delete('/product/:id', deleteProduct);

// Update
router.get('/update', (req, res) => {})
router.get('/update/:id', (req, res) => {})
router.put('/update/:id', 
    body('title').optional(), 
    body('body').optional(),
    body('status').isIn(['IN_PROGRESS', 'SHIPPED', 'DEPRECATED']),
    body('version').optional(),
    (req, res) => {})
router.post('/update',
    body('title').exists().isString(), 
    body('body').exists().isString(),
    (req, res) => {})
router.delete('/update/:id', (req, res) => {})

// Update Point
router.get('/updatepoint', (req, res) => {})
router.get('/updatepoint/:id', (req, res) => {})
router.put('/updatepoint/:id', 
    body('name').optional().isString(),
    body('description').optional().isString(),
    (req, res) => {})
router.post('/updatepoint',
    body('name').isString(),
    body('description').isString(),
    body('updateId').exists().isString(),
    (req, res) => {})
router.delete('/updatepoint/:id', (req, res) => {})

export default router;