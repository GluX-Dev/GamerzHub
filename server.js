import express from "express"
import cors from "cors"
import https from "https"
import dotenv from "dotenv"

// Load environment variables
dotenv.config()

const app = express()
const PORT = process.env.PORT || 3000
const FRONTEND_URL = process.env.FRONTEND_URL || "https://gamerzhubgh.web.app"

// CORS configuration - allow requests from the frontend
app.use(
  cors({
    origin: [FRONTEND_URL, "*"],
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With"],
    credentials: true,
  }),
)

// Body parsers
app.use(express.json())
app.use(express.urlencoded({ extended: true }))

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

    console.log(`Making ${method} request to Paystack: ${path}`)

    const req = https.request(options, (res) => {
      let responseData = ""

      res.on("data", (chunk) => {
        responseData += chunk
      })

      res.on("end", () => {
        try {
          const parsedData = JSON.parse(responseData)
          console.log("Paystack response status:", parsedData.status)
          resolve(parsedData)
        } catch (error) {
          console.error("Failed to parse Paystack response:", error)
          reject(new Error(`Failed to parse Paystack response: ${error.message}`))
        }
      })
    })

    req.on("error", (error) => {
      console.error("Paystack request error:", error)
      reject(new Error(`Paystack request failed: ${error.message}`))
    })

    if (data) {
      console.log("Sending data to Paystack:", {
        ...data,
        amount: data.amount,
        email: data.email,
      })
      req.write(JSON.stringify(data))
    }

    req.end()
  })
}

// Initialize payment
app.post("/api/payment/initialize", async (req, res) => {
  console.log("Payment initialization request received")

  try {
    const { email, amount, metadata, tournamentId, registrationId } = req.body

    if (!email || !amount) {
      console.log("Missing required fields:", { email, amount })
      return res.status(400).json({
        status: false,
        message: "Email and amount are required",
      })
    }

    // Convert amount to pesewa (Paystack uses pesewa for GHS, which is 1/100 of a Cedi)
    const amountInPesewa = Math.floor(Number.parseFloat(amount) * 100)

    // Construct callback URL with all necessary parameters
    const callbackUrl = `${FRONTEND_URL}/payment-callback.html?tournamentId=${tournamentId || ""}&registrationId=${registrationId || ""}`

    const paymentData = {
      email,
      amount: amountInPesewa,
      currency: "GHS", // Explicitly set currency to Ghanaian Cedis
      metadata: metadata || {},
      callback_url: callbackUrl,
    }

    console.log("Initializing payment with data:", {
      email: paymentData.email,
      amount: `${amountInPesewa} pesewas (${amount} GHS)`,
      callback_url: callbackUrl,
    })

    const response = await paystackRequest("POST", "/transaction/initialize", paymentData)

    console.log("Payment initialization response:", {
      status: response.status,
      message: response.message,
      authorizationUrl: response.data?.authorization_url,
    })

    return res.status(200).json(response)
  } catch (error) {
    console.error("Payment initialization error:", error)
    return res.status(500).json({
      status: false,
      message: "Failed to initialize payment: " + error.message,
      error: error.message,
    })
  }
})

// Verify payment
app.get("/api/payment/verify", async (req, res) => {
  console.log("Payment verification request received")

  try {
    const { reference } = req.query

    if (!reference) {
      console.log("Missing reference parameter")
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
      message: "Failed to verify payment: " + error.message,
      error: error.message,
    })
  }
})

// Root path - just return a simple JSON response
app.get("/", (req, res) => {
  res.json({
    status: "ok",
    message: "GamerzHub Payment Server is running",
    endpoints: [
      { method: "POST", path: "/api/payment/initialize", description: "Initialize a payment" },
      { method: "GET", path: "/api/payment/verify", description: "Verify a payment" },
      { method: "GET", path: "/api/health", description: "Health check" },
    ],
  })
})

// Health check endpoint
app.get("/api/health", (req, res) => {
  res.status(200).json({ status: "ok", message: "Server is running" })
})

// Start server
app.listen(PORT, () => {
  console.log(`Payment server running on port ${PORT}`)
  console.log(`This server handles API requests from ${FRONTEND_URL}`)
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

