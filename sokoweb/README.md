# SokoWeb - Decentralized Commerce Network

## 🌐 Overview

SokoWeb is a distributed commerce platform that enables peer-to-peer product and service listings with powerful search and discovery capabilities. Built on decentralized technology, it allows users to create, manage, and discover listings across the network.

## 🚀 Quick Start Guide

Install and launch SokoWeb with these simple commands:

```bash
pip install sokoweb

# Start in interactive mode
sokoweb-up

# Or start in detached mode
sokoweb-up -d
```

### Configuration

During startup, you'll be prompted to configure:

| Parameter | Default | Description |
|-----------|---------|-------------|
| NODE_PORT | 8000 | HTTP API port |
| NODE_TCP_PORT | 8500 | TCP communication port |
| ADVERTISE_IP | localhost | Your node's public address |

> **Important:** For full network participation, use a public IP or domain name. Localhost mode works for testing but won't connect to the wider network. Note that tunneling services like Ngrok are not compatible as SokoWeb requires direct UDP and TCP access.

## 💻 System Requirements

- Python 3.9 or higher
- Docker 27.3.1 or higher
- docker compose 2.29.7 or higher

## 📚 API Reference

### Authentication

#### Create a New User Account

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

#### Obtain Access Token

```bash
curl -X POST http://localhost:8000/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=alice&password=alice123&scope=products:write products:read credits:manage"
```

#### Available Permission Scopes

| Scope | Description |
|-------|-------------|
| products:write | Create and modify product listings |
| products:read | View product listings |
| credits:manage | Purchase and manage account credits |
| categories:write | Suggest new product categories |
| categories:read | View available categories |

### Product Management

#### Create a New Product Listing

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

#### Upload Product Images

```bash
curl -X POST http://localhost:8000/products/{product_id}/image \
  -H "Authorization: Bearer <your_token>" \
  -F "image=@/path/to/image.jpg"
```

### Product Retrieval

#### Get Product by ID

```bash
curl http://localhost:8000/products/{product_id} \
  -H "Authorization: Bearer <your_token>"
```

#### Search by Category or Shop

```bash
curl "http://localhost:8000/products?category=Electronics&shop_name=Tech%20Store" \
  -H "Authorization: Bearer <your_token>"
```

#### Location-Based Search

Find products within a specific radius (in kilometers):

```bash
curl "http://localhost:8000/products?latitude=-1.2921&longitude=36.8219&radius_km=10" \
  -H "Authorization: Bearer <your_token>"
```

#### Combined Search Parameters

Combine multiple search criteria for precise results:

```bash
curl "http://localhost:8000/products?category=Electronics&latitude=-1.2921&longitude=36.8219&radius_km=5" \
  -H "Authorization: Bearer <your_token>"
```

### Image Retrieval

#### Get Primary Product Image

```bash
curl "http://localhost:8000/products/{product_id}/image" \
  -H "Authorization: Bearer <your_token>"
```

This endpoint returns the raw image data that can be:
- Saved directly to a file using curl's `-o` option
- Viewed in tools like Postman that can render binary responses

#### Download All Product Images

```bash
curl "http://localhost:8000/products/{product_id}/images" \
  -H "Authorization: Bearer <your_token>" \
  --output images_{product_id}.zip
```

This endpoint returns a ZIP archive containing all images associated with the product. The response is binary data that should be saved to disk and opened with any ZIP-compatible program.

### Credits System

#### Check Account Balance

```bash
curl http://localhost:8000/credits/balance \
  -H "Authorization: Bearer <your_token>"
```

#### Purchase Additional Credits

```bash
curl -X POST http://localhost:8000/credits/purchase \
  -H "Authorization: Bearer <your_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "amount": 100,
    "phone_number": "+254712345678"
  }'
```

### Marketplace

The marketplace allows node operators to sell earned credits to other users.

#### List All Available Credit Offers

```bash
curl http://localhost:8000/market/offers \
  -H "Authorization: Bearer <your_token>"
```

#### Create a New Credit Sale Offer

```bash
curl -X POST http://localhost:8000/market/offer \
  -H "Authorization: Bearer <your_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "amount": 50,
    "price_per_credit": 1
  }'
```

> **Note:** Only credits beyond the free threshold (100 credits) can be sold.

#### Purchase Credits from an Offer

```bash
curl -X POST http://localhost:8000/market/buy/{offer_id} \
  -H "Authorization: Bearer <your_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "phone_number": "+254712345678"
  }'
```

This initiates an M-Pesa STK push payment. Once the payment is confirmed, credits are transferred from the seller to the buyer.

### Category Management

```bash
# Suggest a new product category
curl -X POST http://<your-public-ip>:8000/categories/suggest \
  -H "Authorization: Bearer <your_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "category_name": "Smart Home"
  }'

# List all available categories
curl http://localhost:8000/categories \
  -H "Authorization: Bearer <your_token>"
```

> **Note:** When deploying to production, replace `localhost` with your server's public IP address or domain name.

## 🔧 Network Management

Monitor and manage your SokoWeb node:

- View running containers: `docker ps`
- Shut down your node: `sokoweb-down`

## 👥 Contributing

SokoWeb is an open-source project and welcomes contributions from the community. Feel free to submit issues, feature requests, or pull requests.

## 📄 License

SokoWeb is released under the MIT License.