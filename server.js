import express from "express"
import cors from "cors"
import https from "https"
import dotenv from "dotenv"
import path from "path"
import { fileURLToPath } from "url"
import fs from "fs"

// Load environment variables
dotenv.config()

const app = express()
const PORT = process.env.PORT || 3000

// Get __dirname equivalent in ES modules
const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

// Middleware
app.use(
  cors({
    origin: ["https://gamerzhub.web.app", "http://localhost:3000", "*"],
    credentials: true,
  }),
)
app.use(express.json())
app.use(express.urlencoded({ extended: true }))
app.use(express.static(path.join(__dirname, "public")))

// Verify Paystack secret key is available
const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY
if (!PAYSTACK_SECRET_KEY) {
  console.error("PAYSTACK_SECRET_KEY is not set in environment variables")
  // Don't exit in production, just log the error
  if (process.env.NODE_ENV !== "production") {
    process.exit(1)
  }
}

// Helper function to make Paystack API requests
function paystackRequest(method, path, data = null) {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: "api.paystack.co",
      port: 443,
      path,
      method,
      headers: {
        Authorization: `Bearer ${PAYSTACK_SECRET_KEY}`,
        "Content-Type": "application/json",
      },
    }

    const req = https.request(options, (res) => {
      let responseData = ""

      res.on("data", (chunk) => {
        responseData += chunk
      })

      res.on("end", () => {
        try {
          const parsedData = JSON.parse(responseData)
          resolve(parsedData)
        } catch (error) {
          reject(new Error(`Failed to parse Paystack response: ${error.message}`))
        }
      })
    })

    req.on("error", (error) => {
      reject(new Error(`Paystack request failed: ${error.message}`))
    })

    if (data) {
      req.write(JSON.stringify(data))
    }

    req.end()
  })
}

// Initialize payment
app.post("/api/payment/initialize", async (req, res) => {
  try {
    const { email, amount, metadata, tournamentId, registrationId } = req.body

    if (!email || !amount) {
      return res.status(400).json({
        status: false,
        message: "Email and amount are required",
      })
    }

    // Convert amount to pesewa (Paystack uses pesewa for GHS, which is 1/100 of a Cedi)
    const amountInPesewa = Math.floor(Number.parseFloat(amount) * 100)

    // Get the host from the request
    const host = req.headers.host
    const protocol = req.headers["x-forwarded-proto"] || "http"
    const baseUrl = `${protocol}://${host}`

    // Construct callback URL with all necessary parameters
    const callbackUrl = `${baseUrl}/payment-callback.html?tournamentId=${tournamentId || ""}&registrationId=${registrationId || ""}`

    const paymentData = {
      email,
      amount: amountInPesewa,
      currency: "GHS", // Explicitly set currency to Ghanaian Cedis
      metadata: metadata || {},
      callback_url: callbackUrl,
    }

    console.log("Initializing payment with data:", {
      ...paymentData,
      amount: `${amountInPesewa} pesewas (${amount} GHS)`,
      callback_url: callbackUrl,
    })

    const response = await paystackRequest("POST", "/transaction/initialize", paymentData)

    console.log("Payment initialization response:", response)

    return res.status(200).json(response)
  } catch (error) {
    console.error("Payment initialization error:", error)
    return res.status(500).json({
      status: false,
      message: "Failed to initialize payment",
      error: error.message,
    })
  }
})

// Verify payment
app.get("/api/payment/verify", async (req, res) => {
  try {
    const { reference } = req.query

    if (!reference) {
      return res.status(400).json({
        status: false,
        message: "Payment reference is required",
      })
    }

    console.log("Verifying payment with reference:", reference)

    const response = await paystackRequest("GET", `/transaction/verify/${reference}`)

    console.log("Payment verification response:", {
      status: response.status,
      paymentStatus: response.data?.status,
      amount: response.data?.amount ? `${response.data.amount / 100} GHS` : "N/A",
      reference: response.data?.reference,
    })

    return res.status(200).json(response)
  } catch (error) {
    console.error("Payment verification error:", error)
    return res.status(500).json({
      status: false,
      message: "Failed to verify payment",
      error: error.message,
    })
  }
})

// Serve HTML directly for root path
app.get("/", (req, res) => {
  // Send a simple HTML response instead of trying to serve a file
  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>GamerzHub Payment Server</title>
        <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700&display=swap" rel="stylesheet">
        <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
        <style>
            body {
                font-family: 'Poppins', sans-serif;
                background-color: #111827;
                color: white;
                min-height: 100vh;
                display: flex;
                flex-direction: column;
            }
            .header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                padding: 0.75rem;
                background-color: #1F2937;
                box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
            }
            .title {
                font-size: 1.25rem;
                font-weight: 700;
                color: #F59E0B;
            }
            .button {
                font-size: 0.875rem;
                background-color: #F59E0B;
                color: #111827;
                padding: 0.25rem 0.75rem;
                border-radius: 0.25rem;
                transition: background-color 0.2s;
                text-decoration: none;
            }
            .button:hover {
                background-color: #D97706;
            }
            .main {
                flex-grow: 1;
                display: flex;
                align-items: center;
                justify-content: center;
                padding: 1rem;
            }
            .card {
                background-color: #1F2937;
                border-radius: 0.5rem;
                box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05);
                padding: 2rem;
                max-width: 28rem;
                width: 100%;
            }
            .center {
                text-align: center;
            }
            .icon-container {
                display: flex;
                justify-content: center;
                margin-bottom: 1rem;
            }
            .icon {
                background-color: #10B981;
                border-radius: 9999px;
                height: 4rem;
                width: 4rem;
                display: flex;
                align-items: center;
                justify-content: center;
            }
            .card-title {
                font-size: 1.25rem;
                font-weight: 700;
                margin-bottom: 0.5rem;
            }
            .card-text {
                color: #9CA3AF;
                margin-bottom: 1.5rem;
            }
            .api-section {
                background-color: #374151;
                border-radius: 0.5rem;
                padding: 1rem;
                margin-bottom: 1.5rem;
                text-align: left;
            }
            .api-title {
                font-weight: 700;
                font-size: 1.125rem;
                margin-bottom: 0.5rem;
            }
            .api-list {
                margin-top: 0.5rem;
                margin-bottom: 0.5rem;
            }
            .api-item {
                display: flex;
                align-items: flex-start;
                margin-bottom: 0.5rem;
            }
            .method {
                background-color: #3B82F6;
                color: white;
                padding: 0.25rem 0.5rem;
                border-radius: 0.25rem;
                font-size: 0.75rem;
                margin-right: 0.5rem;
                margin-top: 0.125rem;
            }
            .method.get {
                background-color: #10B981;
            }
            .endpoint-details {
                font-size: 0.875rem;
            }
            .endpoint-name {
                font-weight: 500;
            }
            .endpoint-desc {
                color: #9CA3AF;
            }
            .footer {
                background-color: #1F2937;
                padding: 1rem;
                border-top: 1px solid #374151;
                text-align: center;
            }
            .footer-text {
                color: #9CA3AF;
                font-size: 0.875rem;
            }
        </style>
    </head>
    <body>
        <header class="header">
            <div>
                <h1 class="title">GamerzHub Payment Server</h1>
            </div>
            <a href="https://gamerzhub.web.app" class="button">Go to GamerzHub</a>
        </header>

        <main class="main">
            <div class="card">
                <div class="center">
                    <div class="icon-container">
                        <div class="icon">
                            <svg xmlns="http://www.w3.org/2000/svg" class="h-8 w-8 text-white" width="32" height="32" fill="none" viewBox="0 0 24 24" stroke="white">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
                            </svg>
                        </div>
                    </div>
                    <h2 class="card-title">Payment Server Online</h2>
                    <p class="card-text">This server handles payment processing for GamerzHub tournaments.</p>
                    
                    <div class="api-section">
                        <h3 class="api-title">API Endpoints</h3>
                        <ul class="api-list">
                            <li class="api-item">
                                <span class="method">POST</span>
                                <div class="endpoint-details">
                                    <p class="endpoint-name">/api/payment/initialize</p>
                                    <p class="endpoint-desc">Initialize a payment transaction</p>
                                </div>
                            </li>
                            <li class="api-item">
                                <span class="method get">GET</span>
                                <div class="endpoint-details">
                                    <p class="endpoint-name">/api/payment/verify</p>
                                    <p class="endpoint-desc">Verify a payment transaction</p>
                                </div>
                            </li>
                            <li class="api-item">
                                <span class="method get">GET</span>
                                <div class="endpoint-details">
                                    <p class="endpoint-name">/api/health</p>
                                    <p class="endpoint-desc">Check server health status</p>
                                </div>
                            </li>
                        </ul>
                    </div>
                    
                    <a href="https://gamerzhub.web.app" class="button" style="display: inline-block; padding: 0.5rem 1rem;">Go to GamerzHub</a>
                </div>
            </div>
        </main>

        <footer class="footer">
            <p class="footer-text">&copy; 2023 GamerzHub. All rights reserved.</p>
        </footer>
    </body>
    </html>
  `)
})

// Handle payment callback route
app.get("/payment-callback", (req, res) => {
  // Check if the file exists
  const callbackPath = path.join(__dirname, "public", "payment-callback.html")

  if (fs.existsSync(callbackPath)) {
    res.sendFile(callbackPath)
  } else {
    // Redirect to the frontend with the query parameters
    const { reference, tournamentId, registrationId } = req.query
    res.redirect(
      `https://gamerzhub.web.app/payment-callback?reference=${reference || ""}&tournamentId=${tournamentId || ""}&registrationId=${registrationId || ""}`,
    )
  }
})

// Health check endpoint
app.get("/api/health", (req, res) => {
  res.status(200).json({ status: "ok", message: "Server is running" })
})

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`)
})

// Handle uncaught exceptions
process.on("uncaughtException", (error) => {
  console.error("Uncaught Exception:", error)
})

// Handle unhandled promise rejections
process.on("unhandledRejection", (reason, promise) => {
  console.error("Unhandled Rejection at:", promise, "reason:", reason)
})

export default app

