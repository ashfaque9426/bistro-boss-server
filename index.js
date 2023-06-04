const express = require('express');
const app = express();
const jwt = require('jsonwebtoken');
require("dotenv").config();
const stripe = require('stripe')(process.env.PAYMENT_SECRET_KEY);
const cors = require('cors');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const port = process.env.PORT || 5000;

// middlewares
app.use(cors());
app.use(express.json());

const verifyJWT = (req, res, next) => {
    const authorization = req.headers.authorization;
    console.log(authorization)
    if(!authorization) {
        return res.status(401).send({error: true, message: "Unauthorized Access"})
    }

    const token = authorization.split(' ')[1];
    jwt.verify(token, process.env.ACESS_TOKEN_SECRET, function (err, decoded) {
        if (err) return res.status(403).send({ error: true, message: "Access Denied" })
        req.decoded = decoded;
        next();
    });
}

// mongodb connection uri
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.5ickmg5.mongodb.net/?retryWrites=true&w=majority`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});

async function run() {
    try {
        // Connect the client to the server	(optional starting in v4.7)
        client.connect();

        const usersCollection = client.db("bistroDB").collection("usersCollection");
        const menuCollection = client.db("bistroDB").collection("menuCollection");
        const reviewCollection = client.db("bistroDB").collection("reviewsCollection");
        const cartCollection = client.db("bistroDB").collection("carts");
        const paymentCollection = client.db("bistroDB").collection("payments");

        app.post('/jwt', (req, res) => {
            const userEmail = req.body;
            const token = jwt.sign(userEmail, process.env.ACESS_TOKEN_SECRET, {expiresIn: '1h'});
            res.send(token);
        })

        // verifyAdmin middleware
        // Warning: use verifyJWT before using verifyAdmin
        const verifyAdmin = async(req, res, next) => {
            const email = req.decoded.email;
            const query = {email: email};
            const user = await usersCollection.findOne(query);
            if(user?.role !== 'admin') return res.status(403).send({error: true, message: 'Forbidden Access'})
            next();
        }

        // users related APIS
        /**
         * 0. do not show secure links to those who should not see the links
         * 1. use jwt token: verifyJWT
         * 2. use verifyAdmin middleware
         */

        app.get('/users', verifyJWT, verifyAdmin, async(req, res)=> {
            const result = await usersCollection.find().toArray();
            res.send(result);
        })

        app.post('/users', async(req, res)=> {
            const user = req.body;
            const query = { email: user.email }
            const existingUser = await usersCollection.findOne(query);
            if(existingUser) {
               return res.send({message: 'user already exists'});
            }
            const result = await usersCollection.insertOne(user);
            res.send(result);
        })

        // security layer: verifyJWT
        // email same
        // check admin
        app.get('/users/admin/:email', verifyJWT, async(req, res) => {
            const email = req.params.email;

            if(req.decoded.email !== email) {
                return res.send({admin: false});
            }

            const query = {
                email: email
            }

            const user = await usersCollection.findOne(query);
            const result = {admin: user?.role === 'admin'}
            res.send(result);
        })

        app.patch('/users/admin/:id', async(req, res) => {
            const id = req.params.id;
            const filter = {_id: new ObjectId(id)};
            const updatedDoc = {
                $set: {
                    role: "admin"
                },
            };
            const result = await usersCollection.updateOne(filter, updatedDoc);
            res.send(result);
        })

        // menu collection
        app.get('/menu', async(req, res) => {
            const result = await menuCollection.find().toArray();
            res.send(result);
        })

        app.post('/menu', verifyJWT, verifyAdmin, async(req, res)=> {
            const newItem = req.body;
            const result = await menuCollection.insertOne(newItem);
            res.send(result);
        })

        app.delete('/menu/:id', verifyJWT, verifyAdmin, async(req, res)=> {
            const id = req.params.id;
            const query = {_id: new ObjectId(id)}
            const result = await menuCollection.deleteOne(query);
            res.send(result);
        })

        app.get('/reviews', async(req, res) => {
            const result = await reviewCollection.find().toArray();
            res.send(result);
        })

        // cart collection
        app.get('/carts', verifyJWT, async(req, res) => {
            const email = req.query.email;
            
            if(!email) {
                res.send([])
            }

            const decodedEmail = req.decoded.email
            if(email !== decodedEmail) return res.status(401).send({error: 1, message: "Forbidden Access"})

            const query = {email: email};
            const result = await cartCollection.find(query).toArray();
            res.send(result);
        })

        app.post('/carts', async(req, res) => {
            const item = req.body;
            const result = await cartCollection.insertOne(item);
            res.send(result);
        })

        app.delete('/carts/:id', async(req, res)=> {
            const id = req.params.id
            const query = {_id: new ObjectId(id)}
            const result = await cartCollection.deleteOne(query);
            res.send(result)
        })

        // create payment intent api
        app.post('/create-payment-intent', verifyJWT, async(req, res)=> {
            const {price} = req.body;
            const amount = parseInt(price * 100);
            const paymentIntent = await stripe.paymentIntents.create({
                amount: amount,
                currency: "usd",
                payment_method_types: ['card']
            });
            res.send({
                clientSecret: paymentIntent.client_secret
            })
        })

        // payment api with user info
        app.post('/payments', verifyJWT, async(req, res) => {
            const payment = req.body;
            payment.menuItems = payment.menuItems.map(strId => new ObjectId(strId));
            const paymentInsertResult = await paymentCollection.insertOne(payment);

            const query = { _id: { $in: payment.cartItems.map(id => new ObjectId(id)) }}
            const deleteResult = await cartCollection.deleteMany(query);
            res.send({ paymentInsertResult, deleteResult});
        })

        // admin stats
        app.get('/admin-stats', verifyJWT, verifyAdmin, async(req, res)=> {
            const users = await usersCollection.estimatedDocumentCount();
            const products = await menuCollection.estimatedDocumentCount();
            const orders = await paymentCollection.estimatedDocumentCount();

            // best way to get sum of a field is to use group and sum operator
            /*
                await paymentCollection.aggregate([
                    {
                        group: {
                            _id: null,
                            total: {$sum: 'price'}
                        }
                    }
                ]).toArray((err, result) => {
                    if(err) {
                        console.error("Error executing the aggregation query:", err);
                        return result;
                    }

                    if(result.length > 0) {
                        console.log('Total sum of prices:', result[0].total);
                    }else {
                        console.log('no result found');
                    }
                })
            */

            const payments = await paymentCollection.find().toArray();
            const revenue = payments.reduce((accu, current) => accu + current.price , 0);

            res.send({ users, products, orders, revenue });
        })

        /**
         * ------------------------------------
         * Bangla System(second best solution)
         * ------------------------------------
         * 1. load all payments
         * 2. for each payment, get the menuItems array
         * 3. for each item in the menuItem array get the menuItem from the menuCollection
         * 4. put them in an array: allOrderedItems
         * 5. sepatate allOrderedItems by category using filter.
         * 6. now get the quantity by using length: pizzas.length
         * 7. for each category use reduce to get the total amount spent on this category.
         * 8. Advanced system is learning aggregate pipeline doing all those things.
         */

        app.get('/order-stats', verifyJWT, verifyAdmin, async(req, res) => {
            const pipeline = [
                {
                    $lookup: {
                        from: 'menuCollection',
                        localField: 'menuItems',
                        foreignField: '_id',
                        as: 'menuItemsData'
                    }
                },
                {
                    $unwind: '$menuItemsData'
                },
                {
                    $group: {
                        _id: '$menuItemsData.category',
                        count: { $sum: 1 },
                        total: { $sum: '$menuItemsData.price' }
                    }
                },
                {
                    $project: {
                        category: '$_id',
                        count: 1,
                        total: { $round: ['$total', 2] },
                        _id: 0
                    }
                }
            ];

            const result = await paymentCollection.aggregate(pipeline).toArray();
            res.send(result);
        })

        // Send a ping to confirm a successful connection
        await client.db("admin").command({ ping: 1 });
        console.log("Pinged your deployment. You successfully connected to MongoDB!");
    } finally {
        // Ensures that the client will close when you finish/error
        // await client.close();
    }
}
run().catch(console.dir);


app.get('/', (req, res) => {
    res.send("Bistro server is running");
});

app.listen(port, () => console.log(`Bistro Boss is sitting on port: ${port}`))

/**
 * ----------------------------------
 *         Naming Convension
 * ----------------------------------
 * users: userCollection
 * app.get('/users/:id')
 * 
 */