const express = require("express");
const jwt = require("jsonwebtoken");
const bodyParser = require("body-parser");
const cors = require('cors');
const { S3Client, PutObjectCommand } = require('@aws-sdk/client-s3');
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const { Client } = require('pg');
require('dotenv').config();

const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

const app = express();
const PORT = process.env.PORT || 8081;

const s3 = new S3Client({
  region: process.env.AWS_REGION,
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  },
});

const config = {
  connectionString: process.env.DB
};

const client = new Client(config);
client.connect();

const corsOptions = {
  origin: '*',
  methods: 'GET,POST,PUT,DELETE,OPTIONS',
  allowedHeaders: 'Content-Type, Authorization',
};

app.use(cors(corsOptions));
app.use(bodyParser.json({ limit: '50mb' }));
app.use(bodyParser.urlencoded({ limit: '50mb', extended: false, parameterLimit: 50000 }));

app.options('*', cors(corsOptions));

app.listen(PORT, () => {
  console.log(`listening on ${PORT}`);
});

function GenerateJWT(_userId, _email, _user_type) {
  return jwt.sign(
    { userId: _userId, email: _email, user_type: _user_type },
    process.env.TOKEN_KEY,
    { expiresIn: "24h" }
  );
}

function verifyToken(req, res, next) {
  const authHeader = req.headers["authorization"];

  if (authHeader) {
    const token = authHeader.split(" ")[1];
    jwt.verify(token, process.env.TOKEN_KEY, (err, user) => {
      if (err) {
        return res.sendStatus(403);
      }

      req.user = user;
      next();
    });
  } else {
    res.sendStatus(401);
  }
}

const upload = multer({ storage: multer.memoryStorage() });

app.get('/', async (req, res) => {
  res.status(200).send("OK");
});

app.post('/login', async (req, res) => {
  if (typeof(req.body.email) === 'undefined' || typeof(req.body.password) === 'undefined') {
    return res.status(200).json({
      status: false,
      data: {},
      message: "Error: Please enter your email and password to login.",
    });
  }

  client.query("SELECT * FROM users WHERE email = $1 AND password = crypt($2, password)", [req.body.email, req.body.password])
    .then((result) => {
      if (result.rows.length > 0) {
        const token = GenerateJWT(result.rows[0].id, result.rows[0].email, result.rows[0].user_type);
       
        res.status(200).json({
          status: true,
          data: {
            userId: result.rows[0].id,
            token: token,
          },
          message: ""
        });
      } else {
        return res.status(200).json({
          status: false,
          data: {},
          message: "Error: Wrong email or Password",
        });
      }
    })
    .catch((e) => {
      console.error(e.stack);
      res.status(500).send(e.stack);
    });
});

app.get('/user', verifyToken, async (req, res) => {
  client.query("SELECT * FROM users")
    .then((result) => {
      return res.status(200).json({
        status: true,
        data: result.rows,
        message: "Success",
      });
    })
    .catch((e) => {
      console.error(e.stack);
      res.status(500).send(e.stack);
    });
});

app.get('/user/:id', verifyToken, async (req, res) => {

  if(req.user.userId == req.params.id || req.user.user_type == 0)
  {
    client.query("SELECT * FROM users WHERE id = $1", [req.params.id])
    .then((result) => {
      if (result.rows.length === 0) {
        return res.status(404).json({
          status: false,
          message: "Error: User not found.",
        });
      }
  
      return res.status(200).json({
        status: true,
        data: result.rows[0],
        message: "Success",
      });
    })
    .catch((e) => {
      console.error(e.stack);
      res.status(500).send(e.stack);
    });
  }
  else
  {
    return res.status(200).json({
      status: false,
      data: "",
      message: "unauthorized",
    });
  }
});

app.post('/user', async (req, res) => {
  if (typeof(req.body.email) === 'undefined' || typeof(req.body.password) === 'undefined') {
    return res.status(200).json({
      status: false,
      data: {},
      message: "Error: Please fill in your email and password to complete the registration process.",
    });
  }

  client.query("SELECT * FROM users WHERE email = $1", [req.body.email])
    .then((result) => {
      if (result.rows.length > 0) {
        return res.status(200).json({
          status: false,
          data: {},
          message: "Error: email has been taken",
        });
      } else {
        client.query("INSERT INTO users (email, username, password) VALUES ($1, $2, crypt($3, gen_salt('bf')))", [req.body.email, req.body.email.split('@')[0], req.body.password])
          .then((result) => {
            res.json({
              status: true,
              data: {},
              message: "Success",
            });
          })
          .catch((e) => {
            console.error(e.stack);
            res.status(500).send(e.stack);
          });
      }
    })
    .catch((e) => {
      console.error(e.stack);
      res.status(500).send(e.stack);
    });
});

app.post('/profile/:id', verifyToken, async (req, res) => {

  if(req.user.userId == req.params.id)
  {
    const result = await client.query("SELECT password FROM users WHERE id = $1 AND password = crypt($2, password)", [req.user.userId, req.body.oldPassword]);
    if(result.rows.length > 0)
    {
      if (req.body.name || req.body.contact) {
        const updates = [];
        const values = [];
        let query = "UPDATE users SET ";

        if (req.body.name) {
          updates.push("name = $" + (values.length + 1));
          values.push(req.body.name);
        }
        if (req.body.contact) {
          updates.push("contact = $" + (values.length + 1));
          values.push(req.body.contact);
        }

        query += updates.join(", ") + " WHERE id = $" + (values.length + 1);
        values.push(targetId);

        await client.query(query, values);
      }

      if (req.body.newPassword)
      {
        await client.query("UPDATE users SET password = crypt($1, gen_salt('bf')) WHERE id = $2", [req.body.newPassword, targetId]);
      }
    }
  }
  else if(req.user.user_type == 0)
  {

    if (req.body.name || req.body.contact) {
      const updates = [];
      const values = [];
      let query = "UPDATE users SET ";

      if (req.body.name) {
        updates.push("name = $" + (values.length + 1));
        values.push(req.body.name);
      }
      if (req.body.contact) {
        updates.push("contact = $" + (values.length + 1));
        values.push(req.body.contact);
      }

      query += updates.join(", ") + " WHERE id = $" + (values.length + 1);
      values.push(targetId);

      await client.query(query, values);
    }
    
    if (req.body.newPassword)
    {
      await client.query("UPDATE users SET password = crypt($1, gen_salt('bf')) WHERE id = $2", [req.body.newPassword, targetId]);
    }
  }
  else
  {
    return res.status(200).json({
      status: false,
      data: "",
      message: "unauthorized",
    });
  }
});

app.get('/products', async (req, res) => {
  const { page = 1, limit = 15 , isHot = false, isFeature = false, categoryId} = req.query;
  const offset = (page - 1) * limit;

  try {
    const countResult = await client.query("SELECT COUNT(*) AS total FROM products");
    const totalItems = parseInt(countResult.rows[0].total, 10);

    let query = "SELECT * FROM products WHERE 1=1";
    const params = [];

    if (isHot === 'true') {
      query += " AND ishot = true";
    }
    if (isFeature === 'true') {
      query += " AND isfeature = true";
    }

    if(categoryId && categoryId != 0)
    {
      query += " AND category_id = "+categoryId;
    }

    query += " LIMIT $1 OFFSET $2";
    const result = await client.query(query, [limit, offset]);

    return res.status(200).json({
      status: true,
      data: result.rows,
      total: totalItems,
      message: "Success",
    });
  } catch (e) {
    console.error(e.stack);
    return res.status(500).send(e.stack);
  }
});

app.get('/product/:id', async (req, res) => {
  client.query("SELECT * FROM products WHERE id = $1", [req.params.id])
    .then((result) => {
      if (result.rows.length === 0) {
        return res.status(404).json({
          status: false,
          message: "Error: Product not found.",
        });
      }

      return res.status(200).json({
        status: true,
        data: result.rows[0],
        message: "Success",
      });
    })
    .catch((e) => {
      console.error(e.stack);
      res.status(500).send(e.stack);
    });
});

app.post('/product', verifyToken, upload.array('images[]', 10), async (req, res) => {
  if (req.user.user_type != 0) {
    return res.status(403).json({
      status: false,
      message: 'Unauthorized',
    });
  }

  const productName = req.body['product-name'];
  const description = req.body['description'];
  const quantity = req.body['quantity'];
  const price = req.body['price'];
  const category = req.body['product-category'];
  const isHot = req.body['is-hot'] === 'on';
  const isFeature = req.body['is-feature'] === 'on';
  const files = req.files;

  if (!files || files.length === 0) {
    return res.status(400).json({
      status: false,
      message: 'Error: Please provide at least one image.',
    });
  }

  try {
    // Upload files to S3 and collect URLs
    const imageUrls = await Promise.all(
      files.map(async (file) => {
        const fileKey = `products/${Date.now()}_${file.originalname}`;
        const uploadParams = {
          Bucket: process.env.AWS_S3_BUCKET,
          Key: fileKey,
          Body: file.buffer,
          ContentType: file.mimetype,
          ACL: 'public-read',
        };

        await s3.send(new PutObjectCommand(uploadParams));
        return `https://${process.env.AWS_S3_BUCKET}.s3.${process.env.AWS_REGION}.amazonaws.com/${fileKey}`;
      })
    );

    // Save product details and image URLs to the database
    const query = `
      INSERT INTO products (product_name, description, qty, price, images, category_id, ishot, isfeature)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
    `;
    const values = [productName, description, quantity, price, JSON.stringify(imageUrls), category, isHot, isFeature];

    await client.query(query, values);

    return res.status(201).json({
      status: true,
      message: 'Product created successfully',
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({
      status: false,
      message: 'Failed to create product',
      error: err.message,
    });
  }
});

app.put('/product/:id', verifyToken, async (req, res) => {
  
  if(req.user.user_type != 0)
    {
      return res.status(200).json({
        status: true,
        data: "",
        message: "unauthorized",
      });
    }

  const productId = req.params.id;
  const { name, description, qty, price, images } = req.body;

  if (!productId) {
    return res.status(400).json({
      status: false,
      message: 'Error: Product ID is required.',
    });
  }

  try {
    const query = `
      UPDATE products 
      SET 
        name = COALESCE($1, name),
        description = COALESCE($2, description),
        qty = COALESCE($3, qty),
        price = COALESCE($4, price),
        images = COALESCE($5, images::jsonb),
        updated_at = NOW()
      WHERE id = $6
    `;
    const values = [name, description, qty, price, images, productId];

    const result = await client.query(query, values);

    if (result.rowCount === 0) {
      return res.status(404).json({
        status: false,
        message: 'Error: Product not found.',
      });
    }

    return res.status(200).json({
      status: true,
      message: 'Product updated successfully.',
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({
      status: false,
      message: 'Error updating product.',
      error: err.message,
    });
  }
});

app.delete('/product/:id', verifyToken, async (req, res) => {

  if (req.user.user_type != 0) {
    return res.status(200).json({
      status: true,
      data: "",
      message: "unauthorized",
    });
  }

  const productId = req.params.id;

  if (!productId) {
    return res.status(400).json({
      status: false,
      message: 'Error: Product ID is required.',
    });
  }

  try {
    const query = `UPDATE products SET deleted_at = NOW() WHERE id = $1 AND deleted_at IS NULL`;
    const values = [productId];

    const result = await client.query(query, values);

    if (result.rowCount === 0) {
      return res.status(404).json({
        status: false,
        message: 'Error: Product not found or already deleted.',
      });
    }

    return res.status(200).json({
      status: true,
      message: 'Product soft deleted successfully.',
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({
      status: false,
      message: 'Error deleting product.',
      error: err.message,
    });
  }
});

app.get('/categories', async (req, res) => {
  client.query("SELECT * FROM categories")
    .then((result) => {
      return res.status(200).json({
        status: true,
        data: result.rows,
        message: "Success",
      });
    })
    .catch((e) => {
      console.error(e.stack);
      res.status(500).send(e.stack);
    });
});

app.get('/carts', verifyToken, async (req, res) => {
  const userId = req.user.userId;

  const cartQuery = await client.query('SELECT * FROM carts WHERE user_id = $1 AND status = 1', [userId]);
  let cart = cartQuery.rows;

  if (cart.length === 0) {
    const newCartQuery = await client.query('INSERT INTO carts (user_id) VALUES ($1) RETURNING *', [userId]);
    cart = newCartQuery.rows;
  }

  const cartItemsQuery = await client.query('SELECT * FROM cart_items WHERE cart_id = $1', [cart[0].id]);
  const cartItems = cartItemsQuery.rows;

  const data = [];

  for (let i = 0; i < cartItems.length; i++) {
    const productQuery = await client.query('SELECT * FROM products WHERE id = $1', [cartItems[i].product_id]);
    if (productQuery.rows.length > 0) {
      const product = productQuery.rows[0];

      data.push({
        id: product.id,
        product_name: product.product_name,
        description: product.description,
        images: product.images,
        price: product.price,
        qty: cartItems[i].qty,
      });
    }
  }

  res.status(200).json({
    status: true,
    data: data,
    message: "",
  });
});

app.post('/carts', verifyToken, async (req, res) => {

  const productId = req.body.productId;
  const qty = req.body.qty;
  const userId = req.user.userId;
  const cartResult = await client.query('SELECT * FROM carts WHERE user_id = $1 AND status = 1 ORDER BY created_at DESC LIMIT 1',[userId]);
  var cartId = -1;

  if (cartResult.rows.length > 0)
    cartId = cartResult.rows[0].id;
  else
    cartId = await client.query('INSERT INTO carts (user_id) VALUES ($1) RETURNING id', [userId]);

  const result = await client.query('INSERT INTO cart_items (cart_id, product_id, qty) VALUES ($1, $2, $3) RETURNING *', [cartId, productId, qty]);

  return res.status(201).json({
    status: true,
    data: result.rows[0],
    message: "Success add product into cart.",
  });
});

app.get('/orders', verifyToken, async (req, res) => {
  client.query("SELECT * FROM orders")
    .then((result) => {
      return res.status(200).json({
        status: true,
        data: result.rows,
        message: "Success",
      });
    })
    .catch((e) => {
      console.error(e.stack);
      res.status(500).send(e.stack);
    });
});

app.get('/orders/:id', verifyToken, async (req, res) => {
  client.query("SELECT * FROM orders WHERE id = $1", [req.params.id])
    .then((result) => {
      if (result.rows.length === 0) {
        return res.status(404).json({
          status: false,
          message: "Error: Order not found.",
        });
      }

      return res.status(200).json({
        status: true,
        data: result.rows[0],
        message: "Success",
      });
    })
    .catch((e) => {
      console.error(e.stack);
      res.status(500).send(e.stack);
    });
});

app.post('/orders', verifyToken, async (req, res) => {
  const { user_id, coupon_code, shipping_address } = req.body;

  // Validate that the user_id and shipping_address are provided
  if (typeof(user_id) === 'undefined' || typeof(shipping_address) === 'undefined') {
    return res.status(400).json({
      status: false,
      message: "Error: Please provide the user_id and shipping_address to create an order.",
    });
  }

  try {
    // Fetch user details
    const userResult = await client.query('SELECT * FROM users WHERE id = $1', [user_id]);

    if (userResult.rows.length > 0) {
      const user = userResult.rows[0];

      // Ensure the user is a customer
      if (user.user_type !== 1) {
        return res.status(403).json({
          status: false,
          message: "Only customers can place orders.",
        });
      }

      // Find the open cart for the user
      const cartResult = await client.query('SELECT * FROM carts WHERE user_id = $1 AND status = 1', [user_id]);

      if (cartResult.rows.length > 0) {
        const cartId = cartResult.rows[0].id;
        const cartItemsResult = await client.query('SELECT * FROM cart_items WHERE cart_id = $1', [cartId]);

        if (cartItemsResult.rows.length > 0) {
          const grossTotal = cartItemsResult.rows.reduce((total, item) => {
            return total + item.price * item.quantity;
          }, 0);

          let discount = 0;
          let couponUsed = null;

          // Apply coupon if provided
          if (coupon_code) {
            const couponResult = await client.query('SELECT * FROM coupons WHERE code = $1 AND qty > 0 AND valid_until > NOW()', [coupon_code]);

            if (couponResult.rows.length > 0) {
              const coupon = couponResult.rows[0];

              // Calculate the discount based on coupon type
              if (coupon.discount_type === 'percent') {
                discount = grossTotal * coupon.discount / 100;
              } else if (coupon.discount_type === 'fixed') {
                discount = coupon.discount;
              }

              // Decrease the coupon quantity by 1
              await client.query('UPDATE coupons SET qty = qty - 1 WHERE id = $1', [coupon.id]);

              couponUsed = coupon_code; // Store the coupon code used
            } else {
              return res.status(400).json({
                status: false,
                message: "Invalid, expired, or out-of-stock coupon.",
              });
            }
          }

          const netTotal = grossTotal - discount;

          // Calculate shipping cost (if any, assuming it's passed or defaulting to 0)
          const shippingCost = 0; // If you want to calculate shipping based on address, you can modify this

          // Create the order with the correct totals and shipping information
          const orderResult = await client.query(
            "INSERT INTO orders (user_id, cart_id, gross_total, net_total, coupon_code, discount, shipping_address, shipping_cost, status) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *",
            [user_id, cartId, grossTotal, netTotal, couponUsed, discount, shipping_address, shippingCost, 'pending']
          );

          // Close the cart by updating its status
          await client.query('UPDATE carts SET status = 0 WHERE id = $1', [cartId]);
          
          const paymentIntent = await stripe.paymentIntents.create({
            amount: netTotal,
            currency: 'myr',
            automatic_payment_methods: {
              enabled: true,
            },
          });

          return res.status(201).json({
            status: true,
            data: {
              order: orderResult.rows[0],
              client_secret: paymentIntent.client_secret
            },
            message: "Order created successfully, and cart has been closed.",
          });

        } else {
          return res.status(400).json({
            status: false,
            message: "No items found in the cart.",
          });
        }
      } else {
        return res.status(400).json({
          status: false,
          message: "No open cart found for the user.",
        });
      }
    } else {
      return res.status(404).json({
        status: false,
        message: "User not found.",
      });
    }
  } catch (error) {
    console.error(error);
    res.status(500).send(error.message);
  }
});