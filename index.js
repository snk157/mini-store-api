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

app.use(cors());
app.use(bodyParser.json({ limit: '50mb' }));
app.use(bodyParser.urlencoded({ limit: '50mb', extended: false, parameterLimit: 50000 }));

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
        client.query("UPDATE users SET last_login = NOW() WHERE id = $1", [result.rows[0].id]);

        res.status(200).json({
          success: true,
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
      status: true,
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

app.get('/products', verifyToken, async (req, res) => {
  client.query("SELECT * FROM products")
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

app.get('/products/:id', verifyToken, async (req, res) => {
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

  const { name, description, qty, price, category, is_hot, is_feature } = req.body;
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
    const values = [name, description, qty, price, JSON.stringify(imageUrls), category, is_hot, is_feature];

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

app.put('/products/:id', verifyToken, async (req, res) => {
  
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

app.get('/categories', verifyToken, async (req, res) => {
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
  const { user_id } = req.body;

  try {
      const userResult = await client.query('SELECT * FROM users WHERE id = $1', [user_id]);

      if (userResult.rows.length > 0) {
          const user = userResult.rows[0];

          const cartResult = await client.query('SELECT * FROM carts WHERE user_id = $1 AND status = 1', [user_id]);

          if (cartResult.rows.length > 0) {
              return res.status(200).json({
                  status: true,
                  data: cartResult.rows[0],
                  message: "Existing open cart found.",
              });
          } else {
              const newCartResult = await client.query('INSERT INTO carts (user_id) VALUES ($1) RETURNING *', [user_id]);

              return res.status(201).json({
                  status: true,
                  data: newCartResult.rows[0],
                  message: "New cart created successfully.",
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

app.post('/carts/:cart_id', verifyToken, async (req, res) => {
  const { user_id, action, product_id, quantity } = req.body;
  const cartId = req.params.cart_id;

  if (typeof(user_id) === 'undefined' || typeof(cartId) === 'undefined' || typeof(action) === 'undefined' || typeof(product_id) === 'undefined' || typeof(quantity) === 'undefined') {
    return res.status(400).json({
      status: false,
      message: "Error: Please provide user_id, cart_id, action, product_id, and quantity.",
    });
  }

  try {
    // Fetch the user to ensure they exist
    const userResult = await client.query('SELECT * FROM users WHERE id = $1', [user_id]);

    if (userResult.rows.length > 0) {
      const user = userResult.rows[0];

      // Ensure the user is a customer
      if (user.user_type !== 1) {
        return res.status(403).json({
          status: false,
          message: "Only customers can modify their cart.",
        });
      }

      // Fetch the cart by user_id and cart_id to ensure it's valid and open (status = 1)
      const cartResult = await client.query('SELECT * FROM carts WHERE id = $1 AND user_id = $2 AND status = 1', [cartId, user_id]);

      if (cartResult.rows.length > 0) {
        const cart = cartResult.rows[0];

        // Action based on the 'action' parameter ('add', 'remove', 'update_quantity')
        if (action === 'add') {
          // Check if item already exists in the cart
          const cartItemResult = await client.query('SELECT * FROM cart_items WHERE cart_id = $1 AND product_id = $2', [cartId, product_id]);

          if (cartItemResult.rows.length > 0) {
            // If item exists, update the quantity
            const updatedItem = await client.query(
              'UPDATE cart_items SET quantity = quantity + $1 WHERE cart_id = $2 AND product_id = $3 RETURNING *',
              [quantity, cartId, product_id]
            );

            return res.status(200).json({
              status: true,
              message: "Item quantity updated in cart.",
              data: updatedItem.rows[0],
            });
          } else {
            // If item does not exist, add it to the cart
            const productResult = await client.query('SELECT * FROM products WHERE id = $1', [product_id]);

            if (productResult.rows.length > 0) {
              const product = productResult.rows[0];

              const addItem = await client.query(
                'INSERT INTO cart_items (cart_id, product_id, price, quantity) VALUES ($1, $2, $3, $4) RETURNING *',
                [cartId, product_id, product.price, quantity]
              );

              return res.status(200).json({
                status: true,
                message: "Item added to cart.",
                data: addItem.rows[0],
              });
            } else {
              return res.status(404).json({
                status: false,
                message: "Product not found.",
              });
            }
          }
        } else if (action === 'remove') {
          // Remove item from cart
          const cartItemResult = await client.query('SELECT * FROM cart_items WHERE cart_id = $1 AND product_id = $2', [cartId, product_id]);

          if (cartItemResult.rows.length > 0) {
            const cartItem = cartItemResult.rows[0];

            // Remove the item completely from the cart
            await client.query('DELETE FROM cart_items WHERE cart_id = $1 AND product_id = $2', [cartId, product_id]);

            return res.status(200).json({
              status: true,
              message: "Item removed from cart.",
            });
          } else {
            return res.status(404).json({
              status: false,
              message: "Item not found in the cart.",
            });
          }
        } else if (action === 'update_quantity') {
          // Update quantity of an item in the cart
          const cartItemResult = await client.query('SELECT * FROM cart_items WHERE cart_id = $1 AND product_id = $2', [cartId, product_id]);

          if (cartItemResult.rows.length > 0) {
            const updatedItem = await client.query(
              'UPDATE cart_items SET quantity = $1 WHERE cart_id = $2 AND product_id = $3 RETURNING *',
              [quantity, cartId, product_id]
            );

            return res.status(200).json({
              status: true,
              message: "Item quantity updated in cart.",
              data: updatedItem.rows[0],
            });
          } else {
            return res.status(404).json({
              status: false,
              message: "Item not found in the cart.",
            });
          }
        } else {
          return res.status(400).json({
            status: false,
            message: "Invalid action. Use 'add', 'remove', or 'update_quantity'.",
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

          return res.status(201).json({
            status: true,
            data: orderResult.rows[0],
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