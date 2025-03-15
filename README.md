# SokoWeb
## Decentralized Commerce Network

A distributed commerce network for peer-to-peer product/service listings, search, and discovery.

### 📋 Overview

SokoWeb enables users to create and discover product listings in a decentralized network, with support for location-based search, image uploads, and credit management.

### 🚀 Quick Start

```bash
pip install sokoweb
sokoweb-up
# or for detached mode
sokoweb-up -d
```

You'll be prompted for:
- `NODE_PORT` (default: 8000)
- `NODE_TCP_PORT` (default: 8500)
- `ADVERTISE_IP` (default: localhost)

> **Note:** Use a public IP/domain to join the network. Localhost works for exploration but won't connect to other nodes. Tunneling services like Ngrok typically won't work as the network requires UDP and TCP access.

### 📋 Requirements

- Python 3.9+
- Docker 27.3.1+
- docker compose 2.29.7+

### 🔑 Authentication

#### Register User

```bash
curl -X POST http://localhost:8000/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice",
    "password": "alice123",
    "email": "alice@example.com",
    "full_name": "Alice Wonderland",
    "phone_number": "+254712345678",
    "scopes": ["products:write", "products:read", "credits:manage"]
  }'
```

#### Get Access Token

```bash
curl -X POST http://localhost:8000/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=alice&password=alice123&scope=products:write products:read credits:manage"
```

Available scopes:
- `products:write` - Create/modify products
- `products:read` - View products
- `credits:manage` - Purchase/manage credits
- `categories:write` - Suggest categories
- `categories:read` - View categories

### 📦 Product Management

#### Post Product

```bash
curl -X POST http://localhost:8000/products \
  -H "Authorization: Bearer <your_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "core": {
      "name": "Smartphone",
      "category": "Electronics",
      "price": 500.00,
      "description": "New smartphone",
      "seller_phone": "+254712345678",
      "shop_name": "Tech Store",
      "seller_location": [-1.2921, 36.8219]
    },
    "extended": {
      "storage_duration_days": 1,
      "tags": ["samsung S21","5G"],
      "metadata": { "color": "black" }
    }
  }'
```

#### Upload Product Image

```bash
curl -X POST http://localhost:8000/products/{product_id}/image \
  -H "Authorization: Bearer <your_token>" \
  -F "image=@/path/to/image.jpg"
```

#### Retrieve Products

By ID:
```bash
curl http://localhost:8000/products/{product_id} \
  -H "Authorization: Bearer <your_token>"
```

Search by category/shop:
```bash
curl "http://localhost:8000/products?category=Electronics&shop_name=Tech%20Store" \
  -H "Authorization: Bearer <your_token>"
```

Search by location (within radius):
```bash
curl "http://localhost:8000/products?latitude=-1.2921&longitude=36.8219&radius_km=10" \
  -H "Authorization: Bearer <your_token>"
```

Combined search:
```bash
curl "http://localhost:8000/products?category=Electronics&latitude=-1.2921&longitude=36.8219&radius_km=5" \
  -H "Authorization: Bearer <your_token>"
```

### 🖼️ Image Retrieval

#### Single Image

```bash
curl "http://localhost:8000/products/{product_id}/image" \
  -H "Authorization: Bearer <your_token>"
```

#### All Images (ZIP)

```bash
curl "http://localhost:8000/products/{product_id}/images" \
  -H "Authorization: Bearer <your_token>" \
  --output images_{product_id}.zip
```

### 💰 Credits Management

#### Check Balance

```bash
curl http://localhost:8000/credits/balance \
  -H "Authorization: Bearer <your_token>"
```

#### Purchase Credits

```bash
curl -X POST http://localhost:8000/credits/purchase \
  -H "Authorization: Bearer <your_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "amount": 100,
    "phone_number": "+254712345678"
  }'
```

### 📂 Category Operations

```bash
# Suggest a new category
curl -X POST http://<your-public-ip>:8000/categories/suggest \
  -H "Authorization: Bearer <your_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "category_name": "Smart Home"
  }'

# Retrieve all categories
curl http://localhost:8000/categories \
  -H "Authorization: Bearer <your_token>"
```

> **Note:** Substitute localhost with your Public IP in production.

### 🔄 Network Management

- View your containers: `docker ps`
- Shut down the network: `sokoweb-down`

### 🤝 Contributing

This project is open source and contributions are welcome.

### 📄 License

MIT License
